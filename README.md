# Kernel-Trace
一个基于uprobe，能同时hook大量用户地址空间函数的kpm内核模块


# 如何使用
在成功加载本项目的kpm模块后(可通过**dmesg | grep +Test-Log+**命令查看详细日志)，再使用项目user目录下的uprobe_trace_user.h文件提供的用户层接口进行编程即可。

**set_module_base**函数用于设置要hook so的基址(打印函数偏移需要用到)。

**set_target_uid**函数用于设置要hook的app的uid(过滤输出需要)。

**set_target_file**函数用于设置要hook so的路径(必须是完整路径)。

**set_fun_offset**函数用于在so文件的指定偏移处设置uprobe挂载点，并可传递指定函数名。

**clear_all_uprobes**函数用于清除所有的uprobe挂载点。

上述函数的返回结果有SET_TRACE_SUCCESS、SET_TRACE_ERROR两种，分别表示设置成功和失败。