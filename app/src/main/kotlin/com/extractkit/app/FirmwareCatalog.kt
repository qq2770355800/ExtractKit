package com.extractkit.app

import android.content.Context
import java.io.File

/**
 * 荣耀 / 华为固件包索引（来自 assets/iknow.tsv）。
 *
 * 每行 7 列，制表符分隔：
 * ```
 * contextId  型号  版本  Android大版本  ?  SP号  发布路径
 * 61100      AAK-AN00  10.0.0.160  10.0  16  SP1C00E160R601P1  ReleaseDoc/HONOR AAK-AN00 ...
 * ```
 * 真正的下载要靠 contextId 去 iknow 服务换直链（见 [IknowResolver]）。
 */
object FirmwareCatalog {

    data class Entry(
        val contextId: String,
        val model: String,
        val version: String,
        val android: String,
        val sp: String,
        val path: String,
    ) {
        val title: String get() = "$model  $version" + if (sp.isNotEmpty()) "（$sp）" else ""
        val subtitle: String get() = path.ifEmpty { "contextNo=W$contextId" }
    }

    private var cache: List<Entry>? = null

    fun all(ctx: Context): List<Entry> {
        cache?.let { return it }
        val list = ArrayList<Entry>(6000)
        runCatching {
            ctx.assets.open("iknow.tsv").bufferedReader().useLines { lines ->
                lines.forEach { line ->
                    if (line.isBlank()) return@forEach
                    val c = line.split('\t')
                    if (c.size < 7) return@forEach
                    if (c[1].isBlank()) return@forEach
                    list.add(
                        Entry(
                            contextId = c[0].trim(),
                            model = c[1].trim(),
                            version = c[2].trim(),
                            android = c[3].trim(),
                            sp = c[5].trim(),
                            path = c[6].trim(),
                        ),
                    )
                }
            }
        }
        // 第二份索引：assets/fw_links.tsv（model|版本|W 编号），条目更全
        val seen = HashSet(list.map { it.contextId.filter { c -> c.isDigit() } })
        runCatching {
            ctx.assets.open("fw_links.tsv").bufferedReader().useLines { lines ->
                lines.forEach { line ->
                    if (line.isBlank()) return@forEach
                    val c = line.split('|')
                    if (c.size < 3) return@forEach
                    val model = c[0].trim()
                    val ver = c[1].trim()
                    val ctxNo = c[2].trim()
                    val digits = ctxNo.filter { it.isDigit() }
                    if (model.isEmpty() || digits.isEmpty() || !seen.add(digits)) return@forEach
                    list.add(Entry(digits, model, ver, "", "", ""))
                }
            }
        }
        cache = list
        return list
    }

    /** 机型名模糊匹配（不区分大小写），空查询返回全部。 */
    fun search(ctx: Context, query: String): List<Entry> {
        val q = query.trim().uppercase()
        val src = all(ctx)
        if (q.isEmpty()) return src
        return src.filter {
            it.model.uppercase().contains(q) ||
                it.version.contains(q) ||
                it.sp.uppercase().contains(q)
        }
    }

    fun models(ctx: Context): List<String> =
        all(ctx).map { it.model }.distinct().sorted()

    /** 当前机型的候选：Build.MODEL 可能带后缀，取前两段做前缀匹配。 */
    fun guessForDevice(ctx: Context, deviceModel: String): String {
        val m = deviceModel.uppercase().trim()
        if (m.isEmpty()) return ""
        val exact = models(ctx).firstOrNull { it.equals(m, ignoreCase = true) }
        if (exact != null) return exact
        val prefix = m.take(3)
        return models(ctx).firstOrNull { it.startsWith(prefix) } ?: m
    }
}
