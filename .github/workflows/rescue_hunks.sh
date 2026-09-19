#!/bin/bash
# =====================================================================
# 🚀 SusFS Total Patch Fixer (ASCII Escape-Safe Edition)
# 场景：GitHub Actions 自动化流水线 (全量、零污染、纯 BASH + AWK)
# 特性：全面采用 ASCII 码及双引号替换脆弱的单引号转义，彻底解决编译阻断
# =====================================================================

set -e

echo "🚀 [SusFS 4.19 Rescue Engine] Adjusting fs/namespace.c for 4.19 VFS context API..."

NAMESPACE_FILE="fs/namespace.c"
if [ -f "$NAMESPACE_FILE" ]; then
echo "[+] Patching $NAMESPACE_FILE..."
    # 修复 Hunk #1 (头文件注入)
    if ! grep -q "CONFIG_KSU_SUSFS" "$NAMESPACE_FILE"; then
        awk '
        /#include "internal.h"/ {
            print "#ifdef CONFIG_KSU_SUSFS"
            print "#include <linux/susfs_def.h>"
            print "#endif // #ifdef CONFIG_KSU_SUSFS"
            print ""
            print $0
            print ""
            print "#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT"
            print "extern bool susfs_is_current_ksu_domain(void);"
            print "extern struct static_key_true susfs_is_sdcard_android_data_not_decrypted;"
            print ""
            print "#define CL_COPY_MNT_NS BIT(25) /* used by copy_mnt_ns() */"
            print "#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT"
            next
        }
        { print }
        ' "$NAMESPACE_FILE" > "${NAMESPACE_FILE}.tmp" && mv "${NAMESPACE_FILE}.tmp" "$NAMESPACE_FILE"
    fi

    # 修复 Hunk #6 (vfs_kern_mount 注入)
    awk '
    BEGIN { in_func = 0; injected = 0; }
    /struct vfsmount \*vfs_kern_mount/ { in_func = 1; }
    in_func == 1 && /mnt = alloc_vfsmnt\(name\);/ && injected == 0 {
        print "#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT"
        print "\tif (static_branch_unlikely(&susfs_is_sdcard_android_data_not_decrypted)) {"
        print "\t\tif (susfs_is_current_ksu_domain()) {"
        print "\t\t\tmnt = susfs_alloc_non_unshare_ksu_vfsmnt(name ?:\"none\");"
        print "\t\t\tgoto bypass_orig_flow;"
        print "\t\t}"
        print "\t}"
        print "#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT"
        print ""
        print $0
        print ""
        print "#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT"
        print "bypass_orig_flow:"
        print "#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT"
        injected = 1
        next
    }
    /^}/ { in_func = 0; }
    { print }
    ' "$NAMESPACE_FILE" > "${NAMESPACE_FILE}.tmp" && mv "${NAMESPACE_FILE}.tmp" "$NAMESPACE_FILE"

    echo "[+] fs/namespace.c patched successfully."
fi


# ---------------------------------------------------------------------
# 2. 修复 fs/proc/cmdline.c (适配带有 IGNORE_SKIP_FLAG 的 4.19 树)
# ---------------------------------------------------------------------
CMDLINE_FILE="fs/proc/cmdline.c"
if [ -f "$CMDLINE_FILE" ]; then
echo "[+] Patching $CMDLINE_FILE..."
    awk '
    BEGIN { header_added = 0; in_func = 0; }
    /static int cmdline_proc_show/ {
        if (!header_added) {
            print "#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG"
            print "extern struct static_key_false susfs_is_fake_cmdline_or_bootconfig_buffer_set;"
            print "extern void susfs_spoof_cmdline_or_bootconfig(struct seq_file *m);"
            print "#endif"
            print ""
            header_added = 1
        }
        in_func = 1
        print $0
        next
    }
    /^{/ {
        print $0
        if (in_func == 1) {
            print "#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG"
            print "\tif (static_branch_likely(&susfs_is_fake_cmdline_or_bootconfig_buffer_set)) {"
            print "\t\tsusfs_spoof_cmdline_or_bootconfig(m);"
            print "\t\tseq_putc(m, \x27\\n\x27);"
            print "\t\treturn 0;"
            print "\t}"
            print "#endif"
            in_func = 0
        }
        next
    }
    /^}/ { in_func = 0; }
    { print }
    ' "$CMDLINE_FILE" > "${CMDLINE_FILE}.tmp" && mv "${CMDLINE_FILE}.tmp" "$CMDLINE_FILE"

    echo "[+] fs/proc/cmdline.c patched successfully."
fi


# ---------------------------------------------------------------------
# 3. 修复 fs/proc/task_mmu.c (函数级状态机隔离，精准防误伤)
# ---------------------------------------------------------------------
TASK_MMU_FILE="fs/proc/task_mmu.c"
if [ -f "$TASK_MMU_FILE" ]; then
echo "[+] Patching $TASK_MMU_FILE..."
    awk '
    BEGIN { in_pagemap = 0; }
    /static ssize_t pagemap_read/ { in_pagemap = 1; print $0; next; }
    
    # 兼容 4.19 down_read_killable 和 mmap_read_lock_killable
    in_pagemap == 1 && (/down_read_killable/ || /mmap_read_lock_killable/) {
        print $0
        getline line2; print line2
        getline line3; print line3
        print "#ifdef CONFIG_KSU_SUSFS_SUS_MAP"
        print "\t\tvma = find_vma(mm, start_vaddr);"
        print "\t\tif (vma && vma->vm_file && SUSFS_IS_INODE_SUS_MAP(file_inode(vma->vm_file)))"
        print "\t\t\tgoto bypass_orig_flow;"
        print "#endif"
        next
    }
    
    in_pagemap == 1 && /walk_page_range/ {
        print $0
        print "#ifdef CONFIG_KSU_SUSFS_SUS_MAP"
        print "bypass_orig_flow:"
        print "#endif"
        in_pagemap = 0
        next
    }
    
    /^}/ { in_pagemap = 0; }
    { print }
    ' "$TASK_MMU_FILE" > "${TASK_MMU_FILE}.tmp" && mv "${TASK_MMU_FILE}.tmp" "$TASK_MMU_FILE"

    echo "[+] fs/proc/task_mmu.c patched successfully."
fi

#---------------------------------------------------------------------
# 4. 修复 fs/super.c
#---------------------------------------------------------------------

SUPER_FILE="fs/super.c"
if [ -f "$SUPER_FILE" ]; then
echo "[+] Patching $SUPER_FILE..."
    # 修复 Hunk #1 (头文件注入)
    if ! grep -q "CONFIG_KSU_SUSFS" "$SUPER_FILE"; then
        awk '
        /#include "internal.h"/ {
            print "#ifdef CONFIG_KSU_SUSFS"
            print "#include <linux/susfs_def.h>"
            print "#endif // #ifdef CONFIG_KSU_SUSFS"
            print $0
            print ""
            print "#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT"
            print "extern bool susfs_is_current_ksu_domain(void);"
            print "extern struct static_key_true susfs_is_sdcard_android_data_not_decrypted;"
            print "#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT"
            next
        }
        { print }
        ' "$SUPER_FILE" > "${SUPER_FILE}.tmp" && mv "${SUPER_FILE}.tmp" "$SUPER_FILE"
    fi

    echo "[+] fs/super.c patched successfully."
fi


echo "🎉 [SusFS Rescue Engine] ASCII-Safe patch completed. Safe to compile now!"
