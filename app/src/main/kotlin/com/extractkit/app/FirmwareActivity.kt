package com.extractkit.app

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.BaseAdapter
import android.widget.EditText
import android.widget.ListView
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * 查询固件包：机型 → 版本列表 → 换取荣耀官方直链。
 * 拿到直链后下载、解出 boot.img，再回到标定页「导入 boot.img」即可。
 */
class FirmwareActivity : AppCompatActivity() {

    private lateinit var search: EditText
    private lateinit var list: ListView
    private lateinit var hint: TextView
    private val adapter = FirmwareAdapter()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_firmware)

        search = findViewById(R.id.etFwSearch)
        list = findViewById(R.id.lvFirmware)
        hint = findViewById(R.id.tvFwHint)
        list.adapter = adapter

        findViewById<View>(R.id.btnFwClose).setOnClickListener { finish() }

        // 默认填当前机型在本索引里的名字（Build.MODEL 可能是 PPG-AN00）
        val guess = FirmwareCatalog.guessForDevice(this, Build.MODEL.orEmpty())
        search.setText(guess)
        search.setSelection(search.text.length)

        search.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) = Unit
            override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) = Unit
            override fun afterTextChanged(s: Editable?) = reload()
        })

        search.setOnEditorActionListener { _, actionId, _ ->
            if (actionId == android.view.inputmethod.EditorInfo.IME_ACTION_SEARCH ||
                actionId == android.view.inputmethod.EditorInfo.IME_ACTION_DONE
            ) {
                val q = search.text.toString().trim()
                if (q.startsWith("http", true) || Regex("^[Ww]?\\d{5,9}$").matches(q)) {
                    hideKeyboard()
                    directExtract(q)
                    return@setOnEditorActionListener true
                }
            }
            false
        }

        list.setOnItemClickListener { _, _, position, _ ->
            val e = adapter.items.getOrNull(position) ?: return@setOnItemClickListener
            hideKeyboard()
            resolveAndShow(e)
        }

        reload()
    }

    private fun reload() {
        val q = search.text.toString()
        val items = FirmwareCatalog.search(this, q).sortedWith(
            compareByDescending<FirmwareCatalog.Entry> { it.version }.thenBy { it.model },
        )
        adapter.items = items
        adapter.notifyDataSetChanged()
        hint.text = if (items.isEmpty()) {
            "没有匹配的固件包（共 ${FirmwareCatalog.all(this).size} 条索引）\n" +
                "也可以粘贴直链或 W 开头编号后回车直接提取"
        } else {
            "找到 ${items.size} 条 · 点一条换取下载直链（也可粘贴直链/编号后回车）"
        }
    }

    /** 换直链要联网，走后台，回来弹窗给复制/分享。 */
    private fun resolveAndShow(entry: FirmwareCatalog.Entry) {
        val dialog = AlertDialog.Builder(this)
            .setTitle(entry.title)
            .setMessage("正在换取下载直链…")
            .setNegativeButton("取消", null)
            .create()
        dialog.setCanceledOnTouchOutside(false)
        dialog.show()

        lifecycleScope.launch {
            val url = withContext(Dispatchers.IO) { IknowResolver.resolve(entry.contextId) }
            if (url == null) {
                dialog.dismiss()
                AlertDialog.Builder(this@FirmwareActivity)
                    .setTitle("换链失败")
                    .setMessage(
                        "contextNo=${IknowResolver.contextNo(entry.contextId)} 没取到直链。\n" +
                            "可能已下架，或当前网络访问不到荣耀的下载服务。",
                    )
                    .setPositiveButton("好", null)
                    .show()
                return@launch
            }
            val size = withContext(Dispatchers.IO) { IknowResolver.sizeOf(url) }
            dialog.dismiss()
            showLinkDialog(entry, url, size)
        }
    }

    private fun showLinkDialog(entry: FirmwareCatalog.Entry, url: String, size: Long) {
        val body = StringBuilder()
        body.appendLine(entry.title)
        body.appendLine("大小 ${IknowResolver.humanSize(size)}")
        body.appendLine()
        body.appendLine(url)

        AlertDialog.Builder(this)
            .setTitle("下载直链")
            .setMessage(body.toString().trimEnd())
            .setPositiveButton("复制") { _, _ ->
                val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                cm.setPrimaryClip(ClipData.newPlainText("firmware", url))
                toast("已复制链接")
            }
            .setNeutralButton("分享") { _, _ ->
                runCatching {
                    startActivity(
                        Intent.createChooser(
                            Intent(Intent.ACTION_SEND).apply {
                                type = "text/plain"
                                putExtra(Intent.EXTRA_TEXT, url)
                            },
                            "分享下载直链",
                        ),
                    )
                }
            }
            .setNegativeButton("提取 boot") { _, _ -> askExtract(entry.title, url) }
            .show()
    }

    /** 只取 boot / init_boot（可选 vendor_boot），不下载整包。 */
    /** 粘贴直链或 W 编号直接提取，不依赖内置索引。 */
    private fun directExtract(raw: String) {
        val box = TextView(this).apply {
            setPadding(56, 48, 56, 48)
            textSize = 14f
            text = "正在换取下载直链…"
        }
        val dialog = AlertDialog.Builder(this)
            .setTitle("直接提取")
            .setView(box)
            .setCancelable(false)
            .setNegativeButton("取消", null)
            .create()
        dialog.show()
        lifecycleScope.launch {
            val url = withContext(Dispatchers.IO) {
                if (raw.startsWith("http", true)) raw else IknowResolver.resolve(raw)
            }
            dialog.dismiss()
            if (url == null) {
                AlertDialog.Builder(this@FirmwareActivity)
                    .setTitle("换链失败")
                    .setMessage("这个编号没取到直链：$raw")
                    .setPositiveButton("好", null)
                    .show()
            } else {
                askExtract("直接提取", url)
            }
        }
    }

    private fun askExtract(nameBase: String, url: String) {
        val opts = arrayOf("boot.img + init_boot.img（默认）", "再加 vendor_boot.img（在包尾，可能几 GB）")
        var vendor = false
        AlertDialog.Builder(this)
            .setTitle("从全量包提取镜像")
            .setSingleChoiceItems(opts, 0) { _, which -> vendor = which == 1 }
            .setMessage("只下载镜像本身那几段，通常几百 MB。")
            .setPositiveButton("开始提取") { _, _ -> runExtract(nameBase, url, vendor) }
            .setNegativeButton("取消", null)
            .show()
    }

    private fun runExtract(nameBase: String, url: String, vendor: Boolean) {
        val box = TextView(this).apply {
            setPadding(56, 48, 56, 48)
            textSize = 14f
            text = "正在读取包结构…"
        }
        val dialog = AlertDialog.Builder(this)
            .setTitle("正在提取")
            .setView(box)
            .setCancelable(false)
            .setNegativeButton("取消", null)
            .create()
        dialog.show()

        lifecycleScope.launch {
            val out = withContext(Dispatchers.IO) {
                runCatching {
                    val plan = FirmwareBootExtractor.plan(url, vendor)
                    val dir = java.io.File(getExternalFilesDir("firmware"), "boot")
                    val name = nameBase.substringBefore(' ').ifBlank { "firmware" }
                    val file = java.io.File(dir, "${name}-boot-images.zip")
                    val tick = { done: Long, cur: String ->
                        runOnUiThread { box.text = cur + "\n\u5df2\u8bfb\u53d6 " + IknowResolver.humanSize(done) }
                    }
                    if (plan.streaming) {
                        // \u5185\u5c42 zip \u662f deflate\uff1a\u53ea\u80fd\u4ece\u8d77\u70b9\u987a\u5e8f\u89e3\u538b\uff0c\u8bfb\u5230\u955c\u50cf\u5c31\u505c
                        FirmwareBootExtractor.extractStreaming(url, plan, file) { done, _, cur -> tick(done, cur) }
                    } else {
                        FirmwareBootExtractor.extract(url, plan, file) { done, total, cur ->
                            val pct = if (total > 0) (done * 100 / total).toInt() else 0
                            runOnUiThread { box.text = cur + "\n$pct%  " + IknowResolver.humanSize(done) + " / " + IknowResolver.humanSize(total) }
                        }
                    }
                }
            }
            dialog.dismiss()
            out.onSuccess { file ->
                AlertDialog.Builder(this@FirmwareActivity)
                    .setTitle("提取完成")
                    .setMessage("${file.name}\n${IknowResolver.humanSize(file.length())}\n\n${file.absolutePath}")
                    .setPositiveButton("导入并标定") { _, _ ->
                        startActivity(
                            Intent(this@FirmwareActivity, GlassCalibrationActivity::class.java)
                                .putExtra("boot_zip", file.absolutePath),
                        )
                    }
                    .setNeutralButton("复制路径") { _, _ ->
                        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        cm.setPrimaryClip(ClipData.newPlainText("boot", file.absolutePath))
                        toast("已复制路径")
                    }
                    .setNegativeButton("关闭", null)
                    .show()
            }.onFailure { e ->
                AlertDialog.Builder(this@FirmwareActivity)
                    .setTitle("提取失败")
                    .setMessage(e.message ?: e.toString())
                    .setPositiveButton("好", null)
                    .show()
            }
        }
    }

    private fun hideKeyboard() {
        (getSystemService(Context.INPUT_METHOD_SERVICE) as android.view.inputmethod.InputMethodManager)
            .hideSoftInputFromWindow(search.windowToken, 0)
        search.clearFocus()
    }

    private fun toast(msg: String) {
        android.widget.Toast.makeText(this, msg, android.widget.Toast.LENGTH_SHORT).show()
    }

    private class FirmwareAdapter : BaseAdapter() {
        var items: List<FirmwareCatalog.Entry> = emptyList()

        override fun getCount(): Int = items.size
        override fun getItem(position: Int): Any = items[position]
        override fun getItemId(position: Int): Long = position.toLong()

        override fun getView(position: Int, convertView: View?, parent: ViewGroup?): View {
            val v = convertView ?: LayoutInflater.from(parent?.context)
                .inflate(R.layout.item_firmware, parent, false)
            val e = items[position]
            v.findViewById<TextView>(R.id.tvFwTitle).text = e.title
            v.findViewById<TextView>(R.id.tvFwSub).text = e.subtitle
            return v
        }
    }
}
