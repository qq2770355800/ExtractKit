package com.extractkit.app

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * 管理器自检：对**每一个**已安装的管理器，跑一遍 ksu_stage.sh 的解析分支
 * （EXTRACTKIT_DRYRUN=1，只解析、不覆盖任何文件），把「会用哪个 ksud、
 * 是不是借用别家的」摊开给用户看。
 *
 * 为什么要这个：包名送错/ksud 借错品牌都会表现成「提权成功但管理器没越狱」，
 * 而那种现象很难从日志里一眼看出根因。自检表把判定提前暴露。
 */
object ManagerAudit {

    data class Row(
        val pkg: String,
        val label: String,
        val src: String,
        val owner: String,
        val cross: Boolean,
        val why: String,
    ) {
        /** shell 域读不了 /data/app，这一项没法判断（不是"缺 ksud"） */
        val noPerm: Boolean get() = why == "noperm"

        /** 一行结论：自我 / 借用 / 缺失 / 无权限 */
        val verdict: String
            get() = when {
                noPerm -> "需 root 才能读"
                src.isBlank() -> "缺 ksud"
                !cross -> "自我"
                owner.isBlank() -> "借用（未知来源）"
                else -> "借用 $owner"
            }

        val isSelf: Boolean get() = !noPerm && src.isNotBlank() && !cross
    }

    private const val DIR = "/data/local/tmp/extract-kit"
    private const val SCRIPT = "$DIR/ksu_stage.sh"
    private const val ASSET = "stage/ksu_stage.sh"

    /** 把脚本推上去（每次覆盖，脚本很小） */
    suspend fun deploy(ctx: Context): Boolean = withContext(Dispatchers.IO) {
        val bytes = runCatching { ctx.assets.open(ASSET).use { it.readBytes() } }.getOrNull()
            ?: return@withContext false
        Shell.exec("mkdir -p $DIR")
        Shell.pushFile(SCRIPT, bytes, executable = true).first == 0
    }

    /** 当前 shell 身份：uid 与 /data/app 可读性（自检表要标出来是谁在跑） */
    suspend fun envInfo(): String = withContext(Dispatchers.IO) {
        val out = Shell.exec("id -u; ls /data/app >/dev/null 2>&1 && echo read-app-ok || echo read-app-denied").second
        val lines = out.lineSequence().map { it.trim() }.filter { it.isNotEmpty() }.toList()
        val uid = lines.firstOrNull() ?: "?"
        val ok = lines.getOrNull(1) == "read-app-ok"
        "uid=$uid" + if (ok) "" else " · 读不到 /data/app"
    }

    /** 单个管理器的解析结果；失败时 src 为空 */
    suspend fun probe(pkg: String): Row = withContext(Dispatchers.IO) {
        val cmd = "EXTRACTKIT_APP_ROOT=/data/app EXTRACTKIT_MGR=$pkg " +
            "EXTRACTKIT_DRYRUN=1 /system/bin/sh $SCRIPT 2>&1"
        val out = Shell.exec(cmd).second
        val line = out.lineSequence()
            .firstOrNull { it.startsWith("[resolve]") && it.contains("mgr=") }
            .orEmpty()
        fun f(key: String): String = Regex("$key=([^ ]*)").find(line)?.groupValues?.get(1).orEmpty()
        Row(
            pkg = pkg,
            label = pkg,
            src = f("src"),
            owner = f("owner"),
            cross = f("cross") == "1",
            why = f("why"),
        )
    }

    /** 对传入的每个包名跑一次，返回顺序与入参一致 */
    suspend fun audit(pkgs: List<String>, labels: Map<String, String>): List<Row> {
        val rows = ArrayList<Row>(pkgs.size)
        for (p in pkgs) {
            val r = probe(p)
            rows += r.copy(label = labels[p] ?: p)
        }
        return rows
    }
}
