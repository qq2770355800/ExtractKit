package com.extractkit.app

import org.junit.Test
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * 不是断言测试，而是"生成器"：读镜像 → 反解 kallsyms / BTF / call site →
 * 打印可直接粘进 ConfigGen.PROFILES 的 Kotlin 片段。
 */
class ProfileGenTest {

    private fun load(path: String): ByteArray? = runCatching {
        val f = File(path)
        if (!f.isFile) return null
        val head = f.inputStream().use { it.readNBytes(8192) }
        if (head.size >= 64 && String(head, 0, 8, Charsets.US_ASCII) == "ANDROID!") {
            val size = ByteBuffer.wrap(head).order(ByteOrder.LITTLE_ENDIAN).getInt(8)
            RandomAccessFile(f, "r").use { raf ->
                raf.seek(4096)
                ByteArray(size).also { raf.readFully(it) }
            }
        } else f.readBytes()
    }.getOrNull()

    private fun emit(label: String, path: String, release: String, prefix: String) {
        val img = load(path) ?: run { println("// $label: 镜像不存在，跳过"); return }
        val r = KallsymsFinder.find(img) { } ?: run { println("// $label: kallsyms 失败"); return }
        val btf = BootImage.extractBtf(img)?.let { Btf.parse(it) }
        val off = btf?.let { b -> runCatching { ConfigGen.offsetsFromBtf(b) }.getOrNull() }
        val cs = CallSiteFinder.find(img, r.symbols, r.relativeBase)
        // 诊断：prepare_creds 里的 bl 都调了谁（5.15 上 cred 站点解不出）
        r.symbols["prepare_creds"]?.let { va ->
            val o = (va - r.relativeBase).toInt()
            val sorted = r.symbols.entries.sortedBy { it.value }
            println("// prepare_creds @0x" + java.lang.Long.toHexString(va))
            var i = 0
            while (i < 0x300) {
                val b0 = img[o + i].toInt() and 0xFF
                val b1 = img[o + i + 1].toInt() and 0xFF
                val b2 = img[o + i + 2].toInt() and 0xFF
                val b3 = img[o + i + 3].toInt() and 0xFF
                val insn = b0 or (b1 shl 8) or (b2 shl 16) or (b3 shl 24)
                if ((insn and -0x04000000) == -0x6C000000) {
                    var imm = insn and 0x03FFFFFF
                    if ((imm and 0x02000000) != 0) imm -= 0x04000000
                    val tgt = va + i + (imm.toLong() shl 2)
                    val near = sorted.minByOrNull { kotlin.math.abs(it.value - tgt) }
                    println("//   +0x${i.toString(16)} -> 0x${java.lang.Long.toHexString(tgt)}  ≈ ${near?.key} (Δ${tgt - (near?.value ?: 0L)})")
                }
                i += 4
            }
        }

        // 自检：linux_banner 必须指向含有 "Linux version" 的字符串
        r.symbols["linux_banner"]?.let { va ->
            val o = (va - r.relativeBase).toInt()
            val txt = String(img, o, minOf(32, img.size - o), Charsets.ISO_8859_1)
            println("// [check] linux_banner @0x" + java.lang.Long.toHexString(va) + " → " + txt.take(20))
        }
        println("// ---- $label ----")
        println("// base=${java.lang.Long.toHexString(r.relativeBase)} symbols=${r.numSyms}")
        if (off == null) {
            println("// BTF 结构体解析失败")
            return
        }
        fun h(v: Int) = "0x" + Integer.toHexString(v).uppercase()
        fun sym(n: String) = r.symbols[n]?.let { "0x" + java.lang.Long.toHexString(it).uppercase() + "uL.toLong()" } ?: "null"
        println(
            """
            Profile(
                name = "$label",
                prefix = "$prefix",
                release = "$release",
                symbols = mapOf(
                    "do_timer_create" to ${sym("do_timer_create")},
                    "selinux_state" to ${sym("selinux_state")},
                    "panic_on_warn" to ${sym("panic_on_warn")},
                    "root_user" to ${sym("root_user")},
                    "init_user_ns" to ${sym("init_user_ns")},
                    "init_ucounts" to ${sym("init_ucounts")},
                    "init_groups" to ${sym("init_groups")},
                ),
                offsets = Offsets(
                    itimerSize = ${h(off.itimerSize)}, itimerNode = ${h(off.itimerNode)},
                    itimerHead = ${h(off.itimerHead)}, itimerElist = ${h(off.itimerElist)},
                    itimerFiring = ${h(off.itimerFiring)}, itimerHandling = ${h(off.itimerHandling)},
                    taskCred = ${h(off.taskCred)}, taskComm = ${h(off.taskComm)},
                    credSize = ${h(off.credSize)}, credUid = ${h(off.credUid)},
                    credSecurity = ${h(off.credSecurity)}, credUser = ${h(off.credUser)},
                    credUserNs = ${h(off.credUserNs)}, credUcounts = ${h(off.credUcounts)},
                    credGroups = ${h(off.credGroups)},
                ),
                measured = Measured(
                    timerSiteOffset = ${cs?.timerOffset?.let { h(it) } ?: "0x94"},
                    credSiteLow21 = ${cs?.credLow21?.let { h(it) } ?: "0x38458"},
                    taskAllocLow21 = ${cs?.taskLow21?.let { h(it) } ?: "0x1CB240"},
                    taskAllocBytes = ${h(btf?.sizeOf("task_struct") ?: 0x12C0)},
                    credReq = ${h(off.credSize)},
                    credAlloc = ${h((off.credSize + 15) / 16 * 16)},
                ),
            ),
            """.trimIndent(),
        )
    }

    @Test
    fun generate() {
        emit(
            "BRM-AN00 / 6.18.21-android17-5",
            "E:/brm_an00/Image",
            "6.18.21-android17-5-ge186062ea75f-abogki564062290-4k",
            "6.18.21-android17-5-ge186062ea75f",
        )
        emit(
            "MTN-AN00 / 6.1.157-android14-11",
            "E:/mtn_an00/boot.img",
            "6.1.157-android14-11-g19a495a97bff",
            "6.1.157-android14-11-g19a495a97bff",
        )
        // MTN-AN80 与 MTN-AN00 是同一份 boot.img（sha256 136b7db0…），
        // 这里故意喂 boot.img 而不是 work/Image —— 后者少了 56 字节前缀，
        // 会让所有 file offset 整体错位，算出假的 call site（0x5C / 0x10C228）。
        emit(
            "MTN-AN80 / 6.1.157-android14-11",
            "F:/MTN-AN80-firmware/img/boot.img",
            "6.1.157-android14-11-g19a495a97bff",
            "6.1.157-android14-11-g19a495a97bff",
        )
        emit(
            "FW135 / 6.6.89-android15-8",
            "D:/fw135/Image",
            "6.6.89-android15-8-g082e5a98dac1-abogki463734347-4k",
            "6.6.89-android15-8-g082e5a98dac1",
        )
        emit(
            "AMG175 / 6.1.157-android14-11",
            "D:/amg175/Image",
            "6.1.157-android14-11-g2646292297b1",
            "6.1.157-android14-11-g2646292297b1",
        )
        emit(
            "PGT-AN10 / 5.15.180-android13-8",
            "F:/PGT-AN10-firmware/Image",
            "5.15.180-android13-8-g1c54d617912d",
            "5.15.180-android13-8-g1c54d617912d",
        )
        emit(
            "PPG / 6.6.89-android15-8",
            "E:/ppg_fw/Image",
            "6.6.89-android15-8-g660f666ec112-abogki430809029-4k",
            "6.6.89-android15-8-g660f666ec112",
        )

        // SER-AN00：boot.img 里是 LZ4 legacy 帧，先用 tools/lz4dec.py 解成裸 Image
        emit(
            "ROD2-W09 / 6.1.157-android14-11",
            "E:/rod2/Image",
            "6.1.157-android14-11-g8d63307071ad",
            "6.1.157-android14-11-g8d63307071ad",
        )

        emit(
            "SER-AN00 / 6.6.118-android15-8",
            "E:/ser_an00/Image",
            "6.6.118-android15-8-gf17133276a57-abogki518694926-4k",
            "6.6.118-android15-8-gf17133276a57",
        )

        emit(
            "BVL-AN16 / 6.1.157-android14-11",
            "E:/bvl_an16/Image",
            "6.1.157-android14-11-g84ffa64b710b",
            "6.1.157-android14-11-g84ffa64b710b",
        )

        emit(
            "6.1.128-g52c266270871",
            "E:/123pan/Downloads/6.1.128/Image",
            "6.1.128-android14-11-g52c266270871",
            "6.1.128-android14-11-g52c266270871",
        )
    }
}
