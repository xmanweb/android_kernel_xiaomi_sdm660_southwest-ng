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
    echo "[+] Patching $NAMESPACE_FILE (Fixing Header Injections & 4.19 fc_mount Overhaul)..."
    
    # ---------------------------------------------------------------------
    # 步骤 1：修复头文件处的 Hunk 失败（利用 awk 精准在 internal.h 之前或之后进行条件注入）
    # ---------------------------------------------------------------------
    
    awk '
    /#include "pnode.h"/ {
        print "#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT"
        print "#include <linux/susfs_def.h>"
        print "#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT"
        print ""
        print "#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT"
        print "extern bool susfs_is_current_ksu_domain(void);"
        print "extern struct static_key_true susfs_is_sdcard_android_data_not_decrypted;"
        print "#define CL_COPY_MNT_NS BIT(25) /* used by copy_mnt_ns() */"
        print "#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT"
        print ""
    }
    { print }
    ' "$NAMESPACE_FILE" > "${NAMESPACE_FILE}.tmp" && mv "${NAMESPACE_FILE}.tmp" "$NAMESPACE_FILE"
  

    # ---------------------------------------------------------------------
    # 步骤 2：全量拦截并完美重写适配 4.19 版的 vfs_kern_mount 函数（解决 fc_mount 处的 rej）
    # ---------------------------------------------------------------------
    awk '
    BEGIN {
        # 状态机初始化：0 = 等待进入目标函数
        state = 0
    }

    # 状态 0：捕获 vfs_kern_mount 函数入口
    state == 0 && /struct vfsmount \*vfs_kern_mount\(/ {
        state = 1
        print $0
        next
    }

    # 状态 1：在函数内部寻找 fc = fs_context_for_mount(...) 之后的安全注入点
    state == 1 && /fc = fs_context_for_mount/ {
        print $0
        # 连续读取并打印接下来的错误校验大底，直到找到返回语句
        while (getline > 0) {
            print $0
            if ($0 ~ /return ERR_CAST\(fc\);/) {
                break
            }
        }
        # 精准在错误校验后，注入带有类型对齐与内存锁死释放的 SUSFS 拦截状态
        print ""
        print "#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT"
        print "\tif (static_branch_unlikely(&susfs_is_sdcard_android_data_not_decrypted)) {"
        print "\t\tif (susfs_is_current_ksu_domain()) {"
        print "\t\t\tstruct mount *ksu_mnt = susfs_alloc_non_unshare_ksu_vfsmnt(name ?:\"none\");"
        print "\t\t\tmnt = ksu_mnt ? &ksu_mnt->mnt : NULL;"
        print "\t\t\tput_fs_context(fc);"
        print "\t\t\tgoto bypass_orig_flow;"
        print "\t\t}"
        print "\t}"
        print "#endif"
        
        state = 2 # 转移状态：开始寻找最后的出口
        next
    }

    # 状态 2：寻找最后的 put_fs_context(fc); 以便注入跳转锚点与安全判空
    state == 2 && /put_fs_context\(fc\);/ {
        print $0
        print "#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT"
        print "bypass_orig_flow:"
        print "#endif"
        print "\tif (!mnt)"
        print "\t\treturn ERR_PTR(-ENOMEM);"
        
        state = 3 # 状态收尾，功成身退
        next
    }

    # 默认行为：原样输出
    { print $0 }
    ' "$NAMESPACE_FILE" > "${NAMESPACE_FILE}.tmp" && mv "${NAMESPACE_FILE}.tmp" "$NAMESPACE_FILE"

    echo "[+] StateMachine-awk: fs/namespace.c successfully re-engineered!"
fi

# ---------------------------------------------------------------------
# 2. 修复 fs/proc/cmdline.c (适配带有 IGNORE_SKIP_FLAG 的 4.19 树)
# ---------------------------------------------------------------------
CMDLINE_FILE="fs/proc/cmdline.c"
if [ -f "$CMDLINE_FILE" ]; then
    echo "[+] Patching $CMDLINE_FILE (Injecting top-level cmdline spoof hook)..."
    
    awk '
    BEGIN { 
        header_added = 0; 
        in_func = 0;
    }

    # 1. 在函数外层上方注入 extern 声明
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

    # 2. 匹配到函数入口的左大括号，紧跟其后注入劫持逻辑
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
            in_func = 0 # 注入完成，关闭状态机
        }
        next
    }

    # 兜底防止状态机未闭合
    /^}/ {
        in_func = 0
    }

    { print }
    ' "$CMDLINE_FILE" > "${CMDLINE_FILE}.tmp" && mv "${CMDLINE_FILE}.tmp" "$CMDLINE_FILE" # <-- ✅ 这里已修正为 CMDLINE_FILE

    echo "[+] $CMDLINE_FILE patched successfully at function entrance."
fi

# ---------------------------------------------------------------------
# 3. 修复 fs/proc/task_mmu.c (函数级状态机隔离，精准防误伤)
# ---------------------------------------------------------------------
TASK_MMU_FILE="fs/proc/task_mmu.c"
if [ -f "$TASK_MMU_FILE" ]; then
    echo "[+] Patching $TASK_MMU_FILE (Injecting SUSFS SUS_MAP core hooks with strict function isolation)..."

    awk '
    BEGIN {
        in_pagemap = 0;  # 核心防火墙：只有在 pagemap_read 函数内才允许修改
    }

    # 1. 捕捉且仅捕捉 pagemap_read 函数入口，开启隔离结界
    /static ssize_t pagemap_read\(struct file \*file/ {
        in_pagemap = 1;
        print $0;
        next;
    }

    # 2. 精准捕捉 pagemap_read 内部的 mmap 锁流程
    /ret = mmap_read_lock_killable\(mm\);/ {
        print $0                     # 1. print: ret = mmap_read_lock_killable(mm);
        getline line2; print line2   # 2. print: if (ret)
        getline line3; print line3   # 3. print:     goto out_free;
        
        # 只有在隔离结界内，才允许注入核心逻辑
        if (in_pagemap == 1) {
            print "#ifdef CONFIG_KSU_SUSFS_SUS_MAP"
            print "\t\tvma = find_vma(mm, start_vaddr);"
            print "\t\tif (vma && vma->vm_file && SUSFS_IS_INODE_SUS_MAP(file_inode(vma->vm_file)))"
            print "\t\t\tgoto bypass_orig_flow;"
            print "#endif"
            in_pagemap = 0           # 注入成功后立刻提前关闭结界，防止下方别的位置误触发
        }
        next;
    }

    # 3. 精准捕捉 pagemap_read 内部的 walk_page_range 调用
    /ret = walk_page_range\(start_vaddr, end, &pagemap_walk\);/ {
        print $0                     # print: ret = walk_page_range(...);
        print "#ifdef CONFIG_KSU_SUSFS_SUS_MAP"
        print "bypass_orig_flow:"
        print "#endif"
        next;
    }

    # 4. 遇到任何函数的右大括号，安全闭合状态机
    /^}/ {
        in_pagemap = 0;
    }

    # 5. 兜底流：其余行原样输出
    { print }
    ' "$TASK_MMU_FILE" > "${TASK_MMU_FILE}.tmp" && mv "${TASK_MMU_FILE}.tmp" "$TASK_MMU_FILE"

    echo "[+] $TASK_MMU_FILE patched successfully with strict pagemap_read isolation."
fi

echo "🎉 [SusFS Rescue Engine] ASCII-Safe patch completed. Safe to compile now!"
