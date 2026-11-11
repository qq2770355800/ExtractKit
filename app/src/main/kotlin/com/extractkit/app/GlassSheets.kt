package com.extractkit.app

import android.content.Context
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.material3.Text
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import androidx.core.graphics.drawable.toBitmap
import androidx.compose.ui.graphics.asImageBitmap

private val SheetInk = Color(0xFF111114)
private val SheetSub = Color(0xFF6B6B72)
private val SheetOk = Color(0xFF12A150)
private val SheetWarn = Color(0xFFB26A00)

internal val GLASS_MANAGERS = linkedMapOf(
    "com.sukisu.ultra" to "SukiSU",
    "io.milksu.manager" to "MilkSU",
    "com.milkcode" to "MilkSU（旧包名）",
    "me.weishu.kernelsu" to "KernelSU",
    "com.resukisu.resukisu" to "SukiSU（旧包名）",
    "com.ghostlock.ksu" to "GhostLock KSU",
    "org.bakasu.bakasu" to "KernelSU Next",
    "com.kowx712.supermanager" to "SuperManager",
    "com.rifsxd.ksunext" to "KernelSU Next (ksunext)",
)

@Composable
private fun Sheet(
    title: String,
    onClose: () -> Unit,
    scrollable: Boolean = true,
    content: @Composable ColumnScope.() -> Unit,
) {
    // 不用 ModalBottomSheet：它是独立 Dialog 窗口，建窗 + 300ms 入场动画会让点击「慢一拍」。
    // 这里直接在同一次组合里画遮罩 + 底部面板，点下去当帧就出现。
    Box(
        Modifier
            .fillMaxSize()
            .background(Color(0x33000000))
            .clickable(
                interactionSource = remember { MutableInteractionSource() },
                indication = null,
            ) { onClose() },
        contentAlignment = Alignment.BottomCenter,
    ) {
        Column(
            Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(topStart = 26.dp, topEnd = 26.dp))
                .background(Color(0xFFFBFBFD))
                .clickable(
                    interactionSource = remember { MutableInteractionSource() },
                    indication = null,
                ) { /* 吃掉点击，别让遮罩把它关掉 */ }
                .padding(horizontal = 22.dp)
                .padding(top = 12.dp, bottom = 28.dp)
                .then(if (scrollable) Modifier.verticalScroll(rememberScrollState()) else Modifier),
        ) {
            Box(
                Modifier
                    .align(Alignment.CenterHorizontally)
                    .width(38.dp)
                    .height(4.dp)
                    .clip(RoundedCornerShape(2.dp))
                    .background(Color(0x33000000)),
            )
            Spacer(Modifier.height(16.dp))
            Text(title, fontSize = 20.sp, fontWeight = FontWeight.SemiBold, color = SheetInk)
            Spacer(Modifier.height(12.dp))
            content()
        }
    }
}

@Composable
private fun RowItem(title: String, sub: String?, accent: Color = SheetSub, onClick: (() -> Unit)? = null, trailing: String? = null) {
    Row(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .then(if (onClick != null) Modifier.clickable { onClick() } else Modifier)
            .padding(vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(title, fontSize = 16.sp, color = SheetInk)
            if (sub != null) Text(sub, fontSize = 12.5.sp, color = accent)
        }
        if (trailing != null) Text(trailing, fontSize = 13.sp, color = accent)
    }
}

/* ---------------- 执行链路 ---------------- */

@Composable
internal fun BackendSheet(onClose: () -> Unit) {
    val ctx = LocalContext.current
    val prefs = remember { ctx.getSharedPreferences("backend", Context.MODE_PRIVATE) }
    var use98937 by remember { mutableStateOf(prefs.getBoolean("use98937", false)) }

    Sheet("执行链路", onClose) {
        RowItem(
            "CVE-2026-98260", "posix timer UAF · 自带 payload",
            if (!use98937) SheetOk else SheetSub, { use98937 = false; prefs.edit().putBoolean("use98937", false).apply() },
            if (!use98937) "✓" else null,
        )
        RowItem(
            "CVE-2026-98937", "原生后端 · 需要本机内核表",
            if (use98937) SheetOk else SheetSub, { use98937 = true; prefs.edit().putBoolean("use98937", true).apply() },
            if (use98937) "✓" else null,
        )
    }
}

/* ---------------- 根管理器 ---------------- */

@Composable
internal fun ManagerSheet(onClose: () -> Unit) {
    val ctx = LocalContext.current
    val pm = ctx.packageManager
    val installed = remember {
        runCatching { pm.getInstalledPackages(0).map { it.packageName }.toSet() }.getOrDefault(emptySet())
    }
    val prefs = remember { ctx.getSharedPreferences("manager", Context.MODE_PRIVATE) }
    var override by remember { mutableStateOf(prefs.getString("pkg", null)) }

    // 0 = 已知管理器，1 = 从已安装应用里选
    var page by remember { mutableIntStateOf(0) }
    var apps by remember { mutableStateOf<List<Pair<AppEntry, androidx.compose.ui.graphics.ImageBitmap?>>?>(null) }
    var query by remember { mutableStateOf("") }
    var pending by remember { mutableStateOf<String?>(null) }

    // APP 页的返回键先回主列表，而不是直接关掉面板
    androidx.activity.compose.BackHandler(enabled = page == 1) {
        page = 0; pending = null; query = ""
    }
    LaunchedEffect(page) {
        if (page == 1 && apps == null) {
            apps = withContext(Dispatchers.IO) { loadAppEntries(ctx) }
        }
    }

    fun save(pkg: String) {
        val info = runCatching { ctx.packageManager.getApplicationInfo(pkg, 0) }.getOrNull()
        val label = info?.let { runCatching { ctx.packageManager.getApplicationLabel(it).toString() }.getOrNull() } ?: pkg
        // 用户选谁就用谁，不再按「像不像管理器」替用户做决定
        override = pkg
        prefs.edit().putString("pkg", pkg).putBoolean("manual", true).apply()
        android.widget.Toast.makeText(ctx, "已设为 $label", android.widget.Toast.LENGTH_SHORT).show()
        page = 0
        pending = null
        query = ""
    }

    val present = GLASS_MANAGERS.filterKeys { it in installed }

    if (page == 0) {
        Sheet("根管理器", onClose) {
            RowItem("自动检测", if (override == null) "当前使用" else "点这里恢复", if (override == null) SheetOk else SheetSub,
                { override = null; prefs.edit().remove("pkg").remove("manual").apply(); onClose() }, if (override == null) "✓" else null)

            present.forEach { (pkg, label) ->
                RowItem(label, pkg, if (override == pkg) SheetOk else SheetSub,
                    { override = pkg; prefs.edit().putString("pkg", pkg).putBoolean("manual", true).apply(); onClose() },
                    if (override == pkg) "✓" else null)
            }

            // 选了一个不在「已知 8 家」里的包，也要能看见
            override?.let { pkg ->
                if (pkg !in present && pkg in installed) {
                    RowItem("手动 · ${displayName(pkg, runCatching { pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString() }.getOrNull(), GLASS_MANAGERS)}",
                        pkg, SheetOk, null, "✓")
                }
            }
            if (present.isEmpty() && override == null) {
                RowItem("没有检测到已知管理器", "可以从下面「已安装应用」里手动挑一个", SheetWarn)
            }

            Spacer(Modifier.height(4.dp))
            RowItem("从已安装应用中选择…", "新品牌 / 改名包 / 隐私空间分身都能选", SheetOk,
                onClick = { page = 1 }, trailing = "›")

        }
        return
    }

    // ---- 已安装应用页 ----
    val all = apps
    val known = GLASS_MANAGERS
    Sheet("选择应用 · ${all?.size ?: "…"}", { page = 0; pending = null; query = "" }, scrollable = false) {
        if (all == null) {
            RowItem("正在读取应用列表…", null, SheetSub)
        } else {
            val filtered = filterApps(all.map { it.first }, query)
            androidx.compose.foundation.text.BasicTextField(
                value = query,
                onValueChange = { query = it },
                singleLine = true,
                textStyle = androidx.compose.ui.text.TextStyle(fontSize = 14.sp, color = SheetInk),
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(14.dp))
                    .background(Color(0xFFF1F1F5))
                    .padding(horizontal = 14.dp, vertical = 10.dp),
                decorationBox = { inner ->
                    if (query.isEmpty()) Text("搜索名称或包名", fontSize = 14.sp, color = Color(0xFF9A9AA2))
                    inner()
                },
            )
            Spacer(Modifier.height(8.dp))
            androidx.compose.foundation.lazy.LazyColumn(Modifier.heightIn(max = 400.dp)) {
                items(filtered.size) { i ->
                    val (entry, icon) = all.first { it.first.pkg == filtered[i].pkg }
                    AppRow(
                        entry = entry,
                        icon = icon,
                        selected = entry.pkg == override,
                        confirming = pending == entry.pkg,
                        // 点哪个就定哪个，不再弹「确认」
                        onPick = { save(entry.pkg) },
                        onConfirm = { save(entry.pkg) },
                        onCancel = { pending = null },
                    )
                }
            }
        }
    }
}

@Composable
private fun AppRow(
    entry: AppEntry,
    icon: androidx.compose.ui.graphics.ImageBitmap?,
    selected: Boolean,
    confirming: Boolean,
    onPick: () -> Unit,
    onConfirm: () -> Unit,
    onCancel: () -> Unit,
) {
    Column {
        Row(
            Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(14.dp))
                .clickable { onPick() }
                .padding(vertical = 9.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            if (icon != null) {
                androidx.compose.foundation.Image(
                    bitmap = icon, contentDescription = null,
                    modifier = Modifier.size(36.dp).clip(RoundedCornerShape(10.dp)),
                )
            } else {
                Box(
                    Modifier.size(36.dp).clip(RoundedCornerShape(10.dp)).background(Color(0xFFEDEDF2)),
                    contentAlignment = Alignment.Center,
                ) { Text(entry.label.take(1).uppercase(), fontSize = 14.sp, color = SheetInk) }
            }
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(entry.label, fontSize = 15.sp, color = SheetInk, maxLines = 1,
                    overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis)
                Text(entry.pkg, fontSize = 11.5.sp, color = SheetSub, maxLines = 1,
                    overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis)
            }
            if (entry.isManager) Text("管理器", fontSize = 11.sp, color = SheetOk)
            if (selected) { Spacer(Modifier.width(8.dp)); Text("✓", fontSize = 13.sp, color = SheetOk) }
        }
        if (confirming) {
            Row(
                Modifier.fillMaxWidth().padding(start = 48.dp, bottom = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text("不像根管理器，仍要指定？", fontSize = 12.sp, color = SheetWarn, modifier = Modifier.weight(1f))
                Text("取消", fontSize = 13.sp, color = SheetSub, modifier = Modifier.clickable { onCancel() })
                Spacer(Modifier.width(16.dp))
                Text("确定", fontSize = 13.sp, color = SheetOk, modifier = Modifier.clickable { onConfirm() })
            }
        }
    }
}

/** 读已安装应用（含图标位图），只在 IO 线程调用。 */
private fun loadAppEntries(ctx: Context): List<Pair<AppEntry, androidx.compose.ui.graphics.ImageBitmap?>> {
    val pm = ctx.packageManager
    val out = ArrayList<Pair<AppEntry, androidx.compose.ui.graphics.ImageBitmap?>>()
    val apps = runCatching { pm.getInstalledApplications(0) }.getOrDefault(emptyList())
    for (ai in apps) {
        val launchable = runCatching { pm.getLaunchIntentForPackage(ai.packageName) != null }.getOrDefault(false)
        val system = (ai.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0
        if (!launchable && system) continue
        val label = runCatching { pm.getApplicationLabel(ai).toString() }.getOrDefault(ai.packageName)
        val entry = AppEntry(ai.packageName, label, isKnownManager(ai.packageName, GLASS_MANAGERS))
        val bmp = runCatching {
            val d = pm.getApplicationIcon(ai)
            d.toBitmap(72, 72).asImageBitmap()
        }.getOrNull()
        out.add(entry to bmp)
    }
    return out.sortedBy { it.first.label.lowercase() }
}

/* ---------------- 运行日志 ---------------- */

@Composable
internal fun LogSheet(onClose: () -> Unit, memory: List<String> = emptyList()) {
    val ctx = LocalContext.current
    val store = remember { LogStore(ctx) }
    // 以前这两行是在 composition 里同步跑：listFiles + 整份 readText 会把面板卡住好几秒。
    // 现在文件列表和正文都放 IO 线程，面板先出来，内容后到。
    var files by remember { mutableStateOf<List<java.io.File>>(emptyList()) }
    var diskLines by remember { mutableStateOf<List<String>>(emptyList()) }
    var loading by remember { mutableStateOf(true) }
    var index by remember { mutableIntStateOf(0) }

    LaunchedEffect(Unit) {
        files = withContext(Dispatchers.IO) { store.history() }
    }
    LaunchedEffect(index, files.size) {
        if (memory.isNotEmpty()) {
            loading = false
            return@LaunchedEffect
        }
        loading = true
        diskLines = withContext(Dispatchers.IO) {
            files.getOrNull(index)?.let { store.tailFrom(it) }?.lines().orEmpty()
        }
        loading = false
    }
    // 内存日志优先（不用等落盘）；LazyColumn 只排版可见的行，600 行也不会卡
    val lines: List<String> = if (memory.isNotEmpty()) memory else diskLines

    val clipboard = androidx.compose.ui.platform.LocalClipboardManager.current
    val listState = rememberLazyListState()
    LaunchedEffect(lines.size) {
        if (lines.isNotEmpty()) listState.animateScrollToItem(lines.size - 1)
    }

    Sheet("运行日志 · ${if (files.isEmpty()) "0" else index + 1}/${files.size}", onClose) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("‹ 上一条", fontSize = 13.sp, color = SheetOk,
                modifier = Modifier.clickable { if (index > 0) index-- })
            Text("下一条 ›", fontSize = 13.sp, color = SheetOk,
                modifier = Modifier.clickable { if (index < files.size - 1) index++ })
            Text("复制", fontSize = 13.sp, color = SheetOk,
                modifier = Modifier.clickable {
                    clipboard.setText(androidx.compose.ui.text.AnnotatedString(lines.joinToString("\n")))
                })
            Spacer(Modifier.weight(1f))
            Text(files.getOrNull(index)?.name ?: "", fontSize = 11.sp, color = SheetSub)
        }
        Spacer(Modifier.height(8.dp))
        if (lines.isEmpty()) {
            Text(if (loading) "读取中…" else "还没有日志", fontSize = 11.5.sp, color = Color(0xFF2E2E33))
        } else {
            androidx.compose.foundation.lazy.LazyColumn(
                state = listState,
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(max = 380.dp)
                    .clip(RoundedCornerShape(12.dp))
                    .background(Color(0x08000000))
                    .padding(12.dp),
            ) {
                items(lines.size) { i ->
                    Text(
                        lines[i],
                        fontSize = 11.5.sp,
                        color = Color(0xFF2E2E33),
                        fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                    )
                }
            }
        }
    }
}

/* ---------------- 支持开发 ---------------- */

@Composable
internal fun SupportSheet(onClose: () -> Unit) {
    val ctx = LocalContext.current
    Sheet("支持开发", onClose) {
        Spacer(Modifier.height(6.dp))
        androidx.compose.foundation.Image(
            painter = androidx.compose.ui.res.painterResource(R.drawable.donate_qr),
            contentDescription = "赞赏码",
            modifier = Modifier
                .fillMaxWidth()
                .height(280.dp)
                .combinedClickable(
                    interactionSource = remember { MutableInteractionSource() },
                    indication = null,
                    onClick = {},
                    onLongClick = { saveQrToGallery(ctx) },
                ),
            contentScale = androidx.compose.ui.layout.ContentScale.Fit,
        )
        Spacer(Modifier.height(4.dp))
        Text(
            "长按图片保存到相册",
            fontSize = 12.5.sp,
            color = SheetSub,
            modifier = Modifier.fillMaxWidth(),
            textAlign = androidx.compose.ui.text.style.TextAlign.Center,
        )
    }
}

/** 长按赞赏码 → 存到相册（Pictures/ExtractKit）。 */
private fun saveQrToGallery(ctx: android.content.Context) {
    runCatching {
        val bmp = android.graphics.BitmapFactory.decodeResource(ctx.resources, R.drawable.donate_qr)
        val values = android.content.ContentValues().apply {
            put(android.provider.MediaStore.Images.Media.DISPLAY_NAME, "extractkit-donate-${System.currentTimeMillis()}.png")
            put(android.provider.MediaStore.Images.Media.MIME_TYPE, "image/png")
            put(android.provider.MediaStore.Images.Media.RELATIVE_PATH,
                android.os.Environment.DIRECTORY_PICTURES + "/ExtractKit")
            put(android.provider.MediaStore.Images.Media.IS_PENDING, 1)
        }
        val uri = ctx.contentResolver.insert(
            android.provider.MediaStore.Images.Media.EXTERNAL_CONTENT_URI, values
        ) ?: error("insert failed")
        ctx.contentResolver.openOutputStream(uri)!!.use { out ->
            bmp.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, out)
        }
        values.clear()
        values.put(android.provider.MediaStore.Images.Media.IS_PENDING, 0)
        ctx.contentResolver.update(uri, values, null, null)
        android.widget.Toast.makeText(ctx, "已保存到相册 · Pictures/ExtractKit", android.widget.Toast.LENGTH_SHORT).show()
    }.onFailure {
        android.widget.Toast.makeText(ctx, "保存失败：${it.message}", android.widget.Toast.LENGTH_SHORT).show()
    }
}

/* ---------------- 已适配内核 ---------------- */

@Composable
internal fun KernelSheet(onClose: () -> Unit) {
    val ctx = LocalContext.current
    val cur = remember { System.getProperty("os.version").orEmpty() }
    val builtin = remember { ConfigGen.PROFILES.map { it.release to it.name } }
    val local = remember { ProfileStore.loadAll(ctx).map { it.release to "本机 / 导入" } }
    Sheet("已适配的内核", onClose) {
        RowItem("当前内核", cur, SheetInk)
        Spacer(Modifier.height(6.dp))
        builtin.forEach { (rel, name) ->
            val hit = rel.take(24).let { cur.startsWith(it) }
            RowItem(
                name,
                ConfigGen.prettyRelease(rel),
                if (hit) SheetOk else SheetSub,
                trailing = if (hit) "★ 已内置" else "已内置",
            )
        }
        local.forEach { (rel, name) ->
            RowItem(name, ConfigGen.prettyRelease(rel), SheetSub, trailing = "本机")
        }
    }
}
