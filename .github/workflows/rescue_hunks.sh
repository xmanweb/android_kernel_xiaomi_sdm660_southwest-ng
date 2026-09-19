#!/bin/bash
# =====================================================================
# 🚀 SusFS Total Patch Fixer (ASCII Escape-Safe Edition)
# 场景：GitHub Actions 自动化流水线 (全量、零污染、纯 BASH + AWK)
# 特性：全面采用 ASCII 码及双引号替换脆弱的单引号转义，彻底解决编译阻断
# =====================================================================

set -e

NAMESPACE_FILE="fs/namespace.c"

if [ -f "$NAMESPACE_FILE" ]; then
    echo "[+] 正在针对 fs_context 架构修复 $NAMESPACE_FILE 中的 vfs_kern_mount..."

    # 1. 头文件补全 (精准检查是否引入了 linux/susfs.h)
    if ! grep -q "linux/susfs.h" "$NAMESPACE_FILE"; then
        echo "  -> [1/2] 正在注入头文件与 SusFS 声明..."
        awk '
        /#include "pnode.h"/ {
            print "#ifdef CONFIG_KSU_SUSFS"
            print "#include <linux/susfs.h>"
            print "#include <linux/susfs_def.h>"
            print "#endif // #ifdef CONFIG_KSU_SUSFS"
            print ""
            print "#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT"
            print "extern bool susfs_is_current_ksu_domain(void);"
            print "extern struct static_key_true susfs_is_sdcard_android_data_not_decrypted;"
            print "#ifndef CL_COPY_MNT_NS"
            print "#define CL_COPY_MNT_NS BIT(25) /* used by copy_mnt_ns() */"
            print "#endif"
            print "#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT"
            print ""
        }
        { print $0 }
        ' "$NAMESPACE_FILE" > "${NAMESPACE_FILE}.tmp" && mv "${NAMESPACE_FILE}.tmp" "$NAMESPACE_FILE"
    fi

    # 2. vfs_kern_mount 函数注入 (仅在 vfs_kern_mount 内部未发现 SUSFS 标记时才注入)
    if ! awk '/vfs_kern_mount\(/, /^}/' "$NAMESPACE_FILE" | grep -q "CONFIG_KSU_SUSFS_SUS_MOUNT"; then
        echo "  -> [2/2] 正在改写 vfs_kern_mount 逻辑..."
        awk '
        BEGIN {
            in_vfs_kern = 0
        }

        # 进入 vfs_kern_mount 函数
        /struct vfsmount \*vfs_kern_mount\(/ {
            in_vfs_kern = 1
            print $0
            next
        }

        # 匹配到 fc 出错校验出口，在其下方注入 SusFS 挂载拦截逻辑
        in_vfs_kern == 1 && /return ERR_CAST\(fc\);/ {
            print $0
            print "#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT"
            print "\tif (static_branch_unlikely(&susfs_is_sdcard_android_data_not_decrypted)) {"
            print "\t\tif (susfs_is_current_ksu_domain()) {"
            print "\t\t\tstruct mount *ksu_mnt = susfs_alloc_non_unshare_ksu_vfsmnt(name ?:\"none\");"
            print "\t\t\tmnt = ksu_mnt ? &ksu_mnt->mnt : NULL;"
            print "\t\t\tput_fs_context(fc);"
            print "\t\t\tgoto bypass_orig_flow;"
            print "\t\t}"
            print "\t}"
            print "#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT"
            next
        }

        # 匹配到 put_fs_context(fc);，在下方注入跳转锚点与 NULL 保护
        in_vfs_kern == 1 && /put_fs_context\(fc\);/ {
            print $0
            print "#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT"
            print "bypass_orig_flow:"
            print "#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT"
            print "\tif (!mnt)"
            print "\t\treturn ERR_PTR(-ENOMEM);"
            next
        }

        # 离开 vfs_kern_mount 函数
        in_vfs_kern == 1 && /^}/ {
            in_vfs_kern = 0
            print $0
            next
        }

        { print $0 }
        ' "$NAMESPACE_FILE" > "${NAMESPACE_FILE}.tmp" && mv "${NAMESPACE_FILE}.tmp" "$NAMESPACE_FILE"
        echo "  [✓] vfs_kern_mount 改写成功！"
    else
        echo "  [!] vfs_kern_mount 已包含 SusFS 逻辑，跳过改写。"
    fi
fi


# ---------------------------------------------------------------------
# 2. 修复 fs/proc/cmdline.c (适配带有 IGNORE_SKIP_FLAG 的 4.19 树)
# ---------------------------------------------------------------------
CMDLINE_FILE="fs/proc/cmdline.c"

if [ -f "$CMDLINE_FILE" ]; then
    echo "[+] Patching $CMDLINE_FILE (Handling CONFIG_INITRAMFS_IGNORE_SKIP_FLAG)..."

    # 检查是否已经注入过，防止重复执行
    if ! grep -q "susfs_spoof_cmdline_or_bootconfig" "$CMDLINE_FILE"; then
        awk '
        BEGIN {
            header_added = 0
            in_func = 0
        }

        # 1. 在 static int cmdline_proc_show 函数上方精准注入 extern 声明
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

        # 2. 捕获函数的入口 '{'，在入口处最优先注入 SUSFS cmdline 伪装/劫持逻辑
        /^{/ && in_func == 1 {
            print $0
            print "#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG"
            print "\tif (static_branch_likely(&susfs_is_fake_cmdline_or_bootconfig_buffer_set)) {"
            print "\t\tsusfs_spoof_cmdline_or_bootconfig(m);"
            print "\t\tseq_putc(m, \x27\\n\x27);"
            print "\t\treturn 0;"
            print "\t}"
            print "#endif"
            in_func = 0  # 注入完成，关闭状态
            next
        }

        { print $0 }
        ' "$CMDLINE_FILE" > "${CMDLINE_FILE}.tmp" && mv "${CMDLINE_FILE}.tmp" "$CMDLINE_FILE"

        echo "[+] $CMDLINE_FILE patched successfully!"
    else
        echo "[!] $CMDLINE_FILE has already been patched, skipping."
    fi
fi


# ---------------------------------------------------------------------
# 3. 修复 fs/proc/task_mmu.c (函数级状态机隔离，精准防误伤)
# ---------------------------------------------------------------------
TASK_MMU_FILE="fs/proc/task_mmu.c"

if [ -f "$TASK_MMU_FILE" ]; then
    echo "[+] Patching $TASK_MMU_FILE (Injecting SUSFS SUS_MAP pagemap_read hooks)..."

    # 1. 补全局部变量定义 (struct vm_area_struct *vma;)
    if ! grep -q "struct vm_area_struct \*vma;" "$TASK_MMU_FILE"; then
        awk '
        /static ssize_t pagemap_read\(struct file \*file/ {
            in_pagemap = 1
            print $0
            next
        }
        in_pagemap == 1 && /int ret = 0, copied = 0;/ {
            print $0
            print "#ifdef CONFIG_KSU_SUSFS_SUS_MAP"
            print "\tstruct vm_area_struct *vma;"
            print "#endif"
            in_pagemap = 0
            next
        }
        { print $0 }
        ' "$TASK_MMU_FILE" > "${TASK_MMU_FILE}.tmp" && mv "${TASK_MMU_FILE}.tmp" "$TASK_MMU_FILE"
    fi

    # 2. 注入 pagemap_read 核心拦截逻辑
    if ! grep -q "bypass_orig_flow" "$TASK_MMU_FILE"; then
        awk '
        BEGIN { in_pagemap = 0; }

        /static ssize_t pagemap_read\(struct file \*file/ {
            in_pagemap = 1
            print $0
            next
        }

        # 匹配到锁解构后注入
        in_pagemap == 1 && /ret = mmap_read_lock_killable\(mm\);/ {
            print $0
            getline; print $0 # if (ret)
            getline; print $0 #     goto out_free;

            print "#ifdef CONFIG_KSU_SUSFS_SUS_MAP"
            print "\t\tvma = find_vma(mm, start_vaddr);"
            print "\t\tif (vma && vma->vm_file && SUSFS_IS_INODE_SUS_MAP(file_inode(vma->vm_file)))"
            print "\t\t\tgoto bypass_orig_flow;"
            print "#endif"
            next
        }

        in_pagemap == 1 && /ret = walk_page_range\(start_vaddr, end, &pagemap_walk\);/ {
            print $0
            print "#ifdef CONFIG_KSU_SUSFS_SUS_MAP"
            print "bypass_orig_flow:"
            print "#endif"
            in_pagemap = 0 # 完成当前函数的改写
            next
        }

        /^}/ { in_pagemap = 0; }

        { print $0 }
        ' "$TASK_MMU_FILE" > "${TASK_MMU_FILE}.tmp" && mv "${TASK_MMU_FILE}.tmp" "$TASK_MMU_FILE"
    fi

    echo "[+] $TASK_MMU_FILE patched successfully!"
fi

#---------------------------------------------------------------------
# 4. 修复 fs/super.c
#---------------------------------------------------------------------

SUPER_FILE="fs/super.c"
if [ -f "$SUPER_FILE" ]; then
    if grep -q "linux/susfs_def.h" "$SUPER_FILE"; then
        echo "[=] $SUPER_FILE already has SusFS headers, skipping."
    else
        echo "[+] Injecting headers & declarations into $SUPER_FILE..."
        awk '
        BEGIN { header_added = 0; }
        /#include "internal.h"/ {
            if (!header_added) {
                print "#ifdef CONFIG_KSU_SUSFS"
                print "#include <linux/susfs_def.h>"
                print "#endif // #ifdef CONFIG_KSU_SUSFS"
                print $0
                print ""
                print "#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT"
                print "extern bool susfs_is_current_ksu_domain(void);"
                print "extern struct static_key_true susfs_is_sdcard_android_data_not_decrypted;"
                print "#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT"
                header_added = 1
                next
            }
        }
        { print }
        ' "$SUPER_FILE" > "${SUPER_FILE}.tmp" && mv "${SUPER_FILE}.tmp" "$SUPER_FILE"
        echo "[+] $SUPER_FILE patched successfully."
    fi
fi


echo "🎉 [SusFS Rescue Engine] ASCII-Safe patch completed. Safe to compile now!"
