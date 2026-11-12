package com.extractkit.app

import androidx.compose.animation.core.animateFloat
import androidx.compose.ui.graphics.nativeCanvas

import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.viewModels
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import rikka.shizuku.Shizuku
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.foundation.clickable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asComposeRenderEffect
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.material3.Text
import com.kyant.backdrop.backdrops.rememberLayerBackdrop
import com.kyant.backdrop.drawBackdrop
import com.kyant.backdrop.effects.blur
import com.kyant.backdrop.effects.lens
import com.kyant.backdrop.effects.vibrancy
import com.kyant.backdrop.highlight.Highlight
import com.kyant.backdrop.backdrops.layerBackdrop
import com.kyant.backdrop.shadow.InnerShadow
import com.kyant.backdrop.shadow.Shadow
import com.kyant.shapes.RoundedRectShape

/** su -c id 的输出里是否真的拿到了 uid=0（"uid=2000" 不算）。 */
internal fun parseSuUid(output: String): Boolean =
    output.lineSequence().any { line ->
        line.contains("uid=0(") || line.trim().startsWith("uid=0 ")
    }

private val MANAGERS = linkedMapOf(
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

internal enum class SheetKind { BACKEND, MANAGER, LOG, SUPPORT, KERNEL }

class GlassMainActivity : ComponentActivity() {

    private val model: RunModel by viewModels()

    private val permListener = Shizuku.OnRequestPermissionResultListener { _, grantResult ->
        model.log("· Shizuku 授权结果：${if (grantResult == 0) "已允许" else "被拒绝"}($grantResult)")
        model.refresh()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val device = "${Build.MANUFACTURER} ${Build.MODEL}".replaceFirstChar { it.uppercase() }
        val kernel = System.getProperty("os.version") ?: "?"
        val backendPrefs = getSharedPreferences("backend", Context.MODE_PRIVATE)
        val adapt = adaptLabel(kernel)
        runCatching { Shizuku.addRequestPermissionResultListener(permListener) }

        setContent {
            var sheet by remember { mutableStateOf<SheetKind?>(null) }
            var backend98937 by remember { mutableStateOf(backendPrefs.getBoolean("use98937", false)) }
            val choice = remember(backend98937, model.rooted, sheet) {
                val ov = managerOverride()
                // 手动选的应用可能不在已知 8 家里，名字从 PackageManager 取，别直接显示包名
                val labels = if (ov != null && ov !in MANAGERS) {
                    MANAGERS + mapOf(ov to appLabel(ov))
                } else MANAGERS
                ManagerChooser.choose(ov, installedPkgs(), MANAGERS.keys.toList(), labels)
            }
            val lifecycleOwner = LocalLifecycleOwner.current

            LaunchedEffect(Unit) { model.refresh() }

            DisposableEffect(lifecycleOwner) {
                val obs = LifecycleEventObserver { _, event ->
                    if (event == Lifecycle.Event.ON_RESUME) model.refresh()
                }
                lifecycleOwner.lifecycle.addObserver(obs)
                onDispose { lifecycleOwner.lifecycle.removeObserver(obs) }
            }

            // 成功后自动打开管理器
            // 一点「开始提权」就把运行日志推上来，进度直接可见
            LaunchedEffect(model.busy) {
                if (model.busy) sheet = SheetKind.LOG
            }

            LaunchedEffect(model.openManager) {
                val pkg = model.consumeOpenManager() ?: return@LaunchedEffect
                val intent = packageManager.getLaunchIntentForPackage(pkg)
                if (intent != null) startActivity(intent) else model.log("! 打不开 $pkg（没找到启动页）")
            }

            // 没有任何日志时不弹面板，直接提示——空面板没意义
            val ctxForToast = androidx.compose.ui.platform.LocalContext.current
            val openLog: () -> Unit = {
                if (model.logs.isEmpty()) {
                    android.widget.Toast.makeText(
                        ctxForToast, "还没有日志，先点「开始提权」", android.widget.Toast.LENGTH_SHORT,
                    ).show()
                } else {
                    sheet = SheetKind.LOG
                }
            }

            val runPrefs = remember { getSharedPreferences("run", MODE_PRIVATE) }
            var safeMode by remember {
                mutableStateOf(runPrefs.getBoolean("safe_mode", false))
            }
            GlassHome(
                device = device,
                kernel = kernel,
                manager = choice.summary,
                backendLabel = backendOf(backend98937),
                adaptLabel = adapt,
                banner = model.banner,
                busy = model.busy,
                safeMode = safeMode,
                onSafeMode = { on ->
                    safeMode = on
                    runPrefs.edit().putBoolean("safe_mode", on).apply()
                },
                onLog = openLog,
                onBanner = {
                    when (model.banner.action) {
                        BannerAction.INSTALL_SHIZUKU -> {
                            val i = packageManager.getLaunchIntentForPackage("moe.shizuku.privileged.api")
                            if (i != null) startActivity(i)
                            else model.log("! 没装 Shizuku（moe.shizuku.privileged.api）")
                        }
                        BannerAction.REQUEST_PERM -> model.requestPermission()
                        BannerAction.OPEN_MANAGER -> {
                            val pkg = choice.pkg
                            val i = pkg?.let { packageManager.getLaunchIntentForPackage(it) }
                            if (i != null) startActivity(i) else sheet = SheetKind.MANAGER
                        }
                        BannerAction.SHOW_LOG -> openLog()
                        BannerAction.NONE -> Unit
                    }
                },
                onRun = { model.start(choice.pkg) },
                onCalib = { open(GlassCalibrationActivity::class.java) },
                onBackend = { sheet = SheetKind.BACKEND },
                onManager = { sheet = SheetKind.MANAGER },
                onSupport = { sheet = SheetKind.SUPPORT },
                onKernel = { sheet = SheetKind.KERNEL },
            )

            // 关闭时保留最后一帧内容做「收下去」动画：sheet 变 null 但 held 还记着是谁
            var held by remember { mutableStateOf<SheetKind?>(null) }
            if (sheet != null) held = sheet
            BackHandler(enabled = sheet != null) { sheet = null }

            androidx.compose.animation.AnimatedVisibility(
                visible = sheet != null,
                enter = androidx.compose.animation.fadeIn(
                    animationSpec = androidx.compose.animation.core.tween(70),
                ),
                exit = androidx.compose.animation.fadeOut(
                    animationSpec = androidx.compose.animation.core.tween(140),
                ) + androidx.compose.animation.slideOutVertically(
                    targetOffsetY = { it / 4 },
                    animationSpec = androidx.compose.animation.core.tween(180),
                ),
            ) {
                when (held) {
                    SheetKind.BACKEND -> BackendSheet(onClose = {
                        sheet = null
                        backend98937 = backendPrefs.getBoolean("use98937", false)
                        AppState.lastBackend98937 = backend98937
                    })
                    SheetKind.MANAGER -> ManagerSheet(onClose = { sheet = null; model.refresh() })
                    SheetKind.LOG -> LogSheet(onClose = { sheet = null }, memory = model.logs)
                    SheetKind.SUPPORT -> SupportSheet(onClose = { sheet = null })
                    SheetKind.KERNEL -> KernelSheet(onClose = { sheet = null })
                    null -> Unit
                }
            }
        }
    }

    override fun onDestroy() {
        runCatching { Shizuku.removeRequestPermissionResultListener(permListener) }
        super.onDestroy()
    }

    /** 四级文案：本机 cfg > 内置 profile > 已收录（未验证）> 未知 */
    private fun adaptLabel(kernel: String): String {
        if (!ConfigGen.isVulnerable(kernel)) return "该内核不在受影响范围"
        val hasCfg = runCatching { ConfigGen.cfgBytesForCurrentKernel(this) != null }.getOrDefault(false)
        if (hasCfg) return "已适配（本机标定）"
        val hit = ConfigGen.PROFILES.firstOrNull { ConfigGen.sameKernel(it.release, kernel) }
        if (hit != null) {
            // 只带 4 个 cred 锚点的那几条走 offsets-only：没有 do_timer_create，靠尺寸软匹配
            val hasText = (hit.symbols["do_timer_create"] ?: 0L) != 0L
            return if (hasText) "已适配（内置 profile）" else "已适配（offsets-only）"
        }
        val known = runCatching { ConfigGen.knownFor(kernel, android.os.Build.MODEL) }.getOrNull()
        if (known != null) {
            val rate = if (known.success + known.failure > 0) {
                " · 成功率 ${known.success * 100 / (known.success + known.failure)}%"
            } else {
                ""
            }
            return "已收录（未验证，需标定）$rate"
        }
        return "内核未知，点「标定」重试"
    }

    private fun open(cls: Class<*>, autorun: Boolean = false) {
        startActivity(Intent(this, cls).putExtra("autorun", autorun))
    }

    /** 只看 su -c id 是否 uid=0（跟主界面的判定一致）。 */
    private fun suAvailable(): Boolean = parseSuUid(runSu())

    private fun runSu(): String = runCatching {
        val p = ProcessBuilder("/system/bin/sh", "-c", "su -c id 2>/dev/null || /system/bin/su -c id 2>/dev/null")
            .redirectErrorStream(true)
            .start()
        val out = p.inputStream.bufferedReader().readText()
        p.waitFor()
        out
    }.getOrDefault("")

    private fun appLabel(pkg: String): String =
        runCatching {
            packageManager.getApplicationLabel(packageManager.getApplicationInfo(pkg, 0)).toString()
        }.getOrDefault(pkg)

    private fun installedPkgs(): Set<String> =
        packageManager.getInstalledPackages(0).map { it.packageName }.toSet()

    /** 手动指定的管理器：只要还装着就用它（选谁是用户的事，这里只清理「已卸载」的残留）。 */
    private fun managerOverride(): String? {
        val prefs = getSharedPreferences("manager", MODE_PRIVATE)
        val pkg = prefs.getString("pkg", null)?.takeIf { it.isNotBlank() } ?: return null
        val installed = runCatching { packageManager.getApplicationInfo(pkg, 0) }.isSuccess
        if (!installed) {
            prefs.edit().remove("pkg").remove("manual").apply()
            return null
        }
        return pkg
    }
}

@Composable
private fun GlassHome(
    device: String,
    kernel: String,
    manager: String,
    backendLabel: String,
    adaptLabel: String,
    banner: Banner,
    busy: Boolean,
    safeMode: Boolean,
    onSafeMode: (Boolean) -> Unit,
    onBanner: () -> Unit,
    onRun: () -> Unit,
    onLog: () -> Unit,
    onCalib: () -> Unit,
    onBackend: () -> Unit,
    onManager: () -> Unit,
    onSupport: () -> Unit,
    onKernel: () -> Unit,
) {
    // 真正的 backdrop：先把页面背景录进图层，卡片再从里面“取景”做折射
    val backdrop = rememberLayerBackdrop()
    val density = LocalDensity.current
    val cornerPx = with(density) { 30.dp.toPx() }
    val shape = remember(cornerPx) { RoundedRectShape(cornerPx) }

    Box(Modifier.fillMaxSize()) {
        // 被采样的背景必须是独立一层（放在 VividBackdropLayer 里），否则卡片会采样到自己 → 栈溢出
        VividBackdropLayer(backdrop)
        Column(
            Modifier
                .fillMaxSize()
                .windowInsetsPadding(WindowInsets.statusBars)
                .padding(horizontal = 18.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Text(
                "ExtractKit",
                fontSize = 32.sp,
                fontWeight = FontWeight.SemiBold,
                color = Color(0xFF111114),
                modifier = Modifier.cardEnter(0),
            )

            GlassRow(
                modifier = Modifier.cardEnter(1),
                backdrop = backdrop, shape = shape,
                title = banner.title,
                value = banner.sub,
                accent = Color(banner.accent),
                onClick = onBanner,
            )

            GlassGroup(backdrop, shape, modifier = Modifier.cardEnter(2)) {
                Row2("设备", device); Row2("内核", kernel)
                ClickRow("内核适配", adaptLabel, onKernel, divider = false)
            }
            GlassGroup(backdrop, shape, modifier = Modifier.cardEnter(3)) {
                ClickRow("执行链路", backendLabel, onBackend)
                ClickRow("标定", "导入本机固件包，解析偏移", onCalib)
                SafeModeRow(safeMode, onSafeMode)
                ClickRow("根管理器", manager, onManager)
                ClickRow("支持开发", "您的细微打赏 都是对开发者的支持", onSupport, divider = false)
            }

            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.Center,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                // 一左一右相向而来，碰一下再弹开：胶囊从左边、日志钮从右边
                Box(Modifier.collideEnter(fromLeft = true)) {
                    GlassPill(if (busy) "执行中…" else "开始提权", backdrop, shape, if (busy) null else onRun)
                }
                Spacer(Modifier.width(10.dp))
                Box(Modifier.collideEnter(fromLeft = false)) {
                    GlassLogButton(backdrop, shape, onLog)
                }
            }
        }
    }
}

@Composable
internal fun Modifier.glass(backdrop: com.kyant.backdrop.Backdrop, shape: com.kyant.shapes.RoundedRectangularShape): Modifier =
    this.drawBackdrop(
        backdrop = backdrop,
        shape = { shape },
        effects = {
            vibrancy()
            blur(2.dp.toPx())
            lens(12.dp.toPx(), 24.dp.toPx())
        },
        highlight = { Highlight.Default.copy(alpha = 0.5f) },
        shadow = { Shadow.Default },
        innerShadow = { InnerShadow.Default },
        onDrawSurface = { drawRect(Color.White.copy(alpha = 0.28f)) },
    )

@Composable
private fun GlassGroup(
    backdrop: com.kyant.backdrop.Backdrop,
    shape: com.kyant.shapes.RoundedRectangularShape,
    modifier: Modifier = Modifier,
    content: @Composable ColumnScope.() -> Unit,
) {
    Column(
        modifier
            .fillMaxWidth()
            .glass(backdrop, shape)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
        content = content,
    )
}

@Composable
private fun GlassRow(
    backdrop: com.kyant.backdrop.Backdrop,
    shape: com.kyant.shapes.RoundedRectangularShape,
    title: String,
    value: String,
    accent: Color,
    onClick: (() -> Unit)? = null,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier
            .fillMaxWidth()
            .glass(backdrop, shape)
            .then(if (onClick != null) Modifier.clickable { onClick() } else Modifier)
            .padding(horizontal = 20.dp, vertical = 18.dp),
    ) {
        Text(title, fontSize = 22.sp, fontWeight = FontWeight.SemiBold, color = Color(0xFF111114))
        Spacer(Modifier.height(4.dp))
        Text(value, fontSize = 14.sp, color = accent)
    }
}

@Composable
private fun ColumnScope.Row2(k: String, v: String) {
    Column {
        Text(k, fontSize = 17.sp, fontWeight = FontWeight.SemiBold, color = Color(0xFF111114))
        Text(v, fontSize = 13.5.sp, color = Color(0xFF6B6B72))
    }
}

@Composable
private fun ColumnScope.ClickRow(
    k: String,
    v: String,
    onClick: () -> Unit,
    hint: String? = null,
    divider: Boolean = true,
) {
    androidx.compose.foundation.layout.Row(
        Modifier.fillMaxWidth().glassClickable(onClick),
        verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(k, fontSize = 17.sp, fontWeight = FontWeight.SemiBold, color = Color(0xFF111114))
            if (v.isNotBlank()) Text(v, fontSize = 13.5.sp, color = Color(0xFF6B6B72))
        }
        if (hint != null) Text(hint, fontSize = 12.5.sp, color = Color(0xFF8A8A92))
        Text("›", fontSize = 18.sp, color = Color(0xFF9A9AA2))
    }
    if (divider) {
        androidx.compose.foundation.layout.Box(
            Modifier
                .fillMaxWidth()
                .height(1.dp)
                .background(Color(0x0F000000))
        )
    }
}

/** 安全模式：加载前把已有模块临时 disable，交接完成后再放开。 */
@Composable
private fun ColumnScope.SafeModeRow(on: Boolean, onChange: (Boolean) -> Unit) {
    androidx.compose.foundation.layout.Row(
        Modifier.fillMaxWidth(),
        verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text("安全模式", fontSize = 17.sp, fontWeight = FontWeight.SemiBold, color = Color(0xFF111114))
            Text(
                if (on) "加载前临时禁用已有模块" else "已有模块保持启用",
                fontSize = 13.5.sp,
                color = Color(0xFF6B6B72),
                maxLines = 1,
            )
        }
        SafeToggle(on, onChange)
    }
    androidx.compose.foundation.layout.Box(
        Modifier
            .fillMaxWidth()
            .height(1.dp)
            .background(Color(0x0F000000))
    )
}

/** 开关：胶囊轨道 + 白色圆钮，开时轨道渐变绿，关时淡灰带细边（对齐 backdrop 示例里的 Toggle）。 */
@Composable
private fun SafeToggle(on: Boolean, onChange: (Boolean) -> Unit) {
    val t by androidx.compose.animation.core.animateFloatAsState(
        targetValue = if (on) 1f else 0f,
        animationSpec = androidx.compose.animation.core.spring(
            dampingRatio = 0.62f,
            stiffness = 900f,
        ),
        label = "safeToggle",
    )
    val trackW = 56.dp
    val trackH = 32.dp
    val knob = 26.dp
    val pad = 3.dp
    val radius = androidx.compose.foundation.shape.RoundedCornerShape(50)
    val track = androidx.compose.ui.graphics.lerp(Color(0x14000000), Color(0xFF35C46A), t)
    val edge = androidx.compose.ui.graphics.lerp(Color(0x22000000), Color(0x0035C46A), t)
    androidx.compose.foundation.layout.Box(
        Modifier
            .size(trackW, trackH)
            .clip(radius)
            .background(track)
            .border(1.dp, edge, radius)
            .clickable(onClick = { onChange(!on) }),
        contentAlignment = androidx.compose.ui.Alignment.CenterStart,
    ) {
        androidx.compose.foundation.layout.Box(
            Modifier
                .padding(horizontal = pad)
                .offset(x = (trackW - knob - pad * 2) * t)
                .size(knob)
                .shadow(1.5.dp, radius)
                .background(Color.White, radius)
        )
    }
}

/** 首页卡片依次从下往上「浮」进来：每个元素错开 70ms。 */
/** 底部两颗：一左一右撞过来，碰一下再各自弹回原位。 */
@Composable
private fun Modifier.collideEnter(fromLeft: Boolean): Modifier {
    var shown by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) {
        kotlinx.coroutines.delay(210L)
        shown = true
    }
    val travel = 118f
    // 弹簧而不是关键帧：落在终点时会自己回弹一下，才有"撞上弹开"的手感
    val dx by androidx.compose.animation.core.animateFloatAsState(
        targetValue = if (shown) 0f else if (fromLeft) -travel else travel,
        animationSpec = androidx.compose.animation.core.spring(
            dampingRatio = 0.52f,
            stiffness = 620f,
            visibilityThreshold = 0.4f,
        ),
        label = if (fromLeft) "pillDx" else "logDx",
    )
    val alpha by androidx.compose.animation.core.animateFloatAsState(
        targetValue = if (shown) 1f else 0f,
        animationSpec = androidx.compose.animation.core.tween(150),
        label = if (fromLeft) "pillA" else "logA",
    )
    // 撞上那一下轻微压扁 + 回弹，靠 delay 对齐弹簧到位的时间
    val squash by androidx.compose.animation.core.animateFloatAsState(
        targetValue = if (shown) 1f else 1f,
        animationSpec = androidx.compose.animation.core.keyframes {
            durationMillis = 560
            1f at 0
            0.95f at 300
            1.02f at 380
            1f at 560
        },
        label = if (fromLeft) "pillS" else "logS",
    )
    return this.graphicsLayer {
        translationX = dx.dp.toPx()
        this.alpha = alpha
        scaleX = squash
        scaleY = squash
    }
}

@Composable
private fun Modifier.cardEnter(index: Int): Modifier {
    var shown by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) {
        kotlinx.coroutines.delay(index * 62L)
        shown = true
    }
    val alpha by androidx.compose.animation.core.animateFloatAsState(
        targetValue = if (shown) 1f else 0f,
        animationSpec = androidx.compose.animation.core.tween(305, easing = androidx.compose.animation.core.FastOutSlowInEasing),
        label = "alpha$index",
    )
    val dy by androidx.compose.animation.core.animateDpAsState(
        targetValue = if (shown) 0.dp else 22.dp,
        animationSpec = androidx.compose.animation.core.tween(330, easing = androidx.compose.animation.core.FastOutSlowInEasing),
        label = "dy$index",
    )
    return this.graphicsLayer {
        this.alpha = alpha
        translationY = dy.toPx()
        val sc = 1f - (dy.value / 22f) * 0.02f
        scaleX = sc
        scaleY = sc
    }
}

/** 圆形玻璃按钮：中间画一个「日志」图标（文档 + 三行横线）。 */
@Composable
private fun GlassLogButton(
    backdrop: com.kyant.backdrop.Backdrop,
    shape: com.kyant.shapes.RoundedRectangularShape,
    onClick: () -> Unit,
) {
    val circle = remember { com.kyant.shapes.CapsuleShape() }
    Box(
        Modifier
            .size(56.dp)
            .glassClickable(onClick)
            .drawBackdrop(
                backdrop = backdrop,
                shape = { circle },
                effects = {
                    vibrancy()
                    blur(2.dp.toPx())
                    lens(10.dp.toPx(), 20.dp.toPx())
                },
                highlight = { Highlight.Default.copy(alpha = 0.5f) },
                shadow = { Shadow.Default },
                innerShadow = { InnerShadow.Default },
                onDrawSurface = { drawRect(Color.White.copy(alpha = 0.18f)) },
            ),
        contentAlignment = Alignment.Center,
    ) {
        Canvas(Modifier.size(22.dp)) {
            val ink = Color(0xFF1A1A1F)
            val w = size.width
            val h = size.height
            val stroke = w * 0.09f
            // 文档外框
            drawRoundRect(
                color = ink,
                topLeft = Offset(0f, 0f),
                size = Size(w, h),
                cornerRadius = CornerRadius(w * 0.16f, w * 0.16f),
                style = Stroke(width = stroke),
            )
            // 三行文字
            val left = w * 0.22f
            listOf(0.32f, 0.5f, 0.68f).forEachIndexed { i, fy ->
                val right = if (i == 2) w * 0.62f else w * 0.78f
                drawLine(
                    color = ink,
                    start = Offset(left, h * fy),
                    end = Offset(right, h * fy),
                    strokeWidth = stroke * 0.9f,
                    cap = StrokeCap.Round,
                )
            }
        }
    }
}

/**
 * 缓慢流动的色带 + 三个漂移光斑。phase 走 0..1 一个循环，
 * 玻璃卡片每帧重新采样背景，所以能看出颜色在玻璃里慢慢游动。
 */
// 水印画笔：每帧都会画，抽出复用，避免 60fps 里反复 new
private val watermarkPaint by lazy {
    android.graphics.Paint(android.graphics.Paint.ANTI_ALIAS_FLAG).apply {
    color = 0x47FFFFFF
    typeface = android.graphics.Typeface.create("serif", android.graphics.Typeface.BOLD)
    textAlign = android.graphics.Paint.Align.CENTER
    letterSpacing = 0.08f
    maskFilter = android.graphics.BlurMaskFilter(22f, android.graphics.BlurMaskFilter.Blur.NORMAL)
}
}

internal fun DrawScope.drawVividBackdrop(phase: Float = 0f) {
    val t = phase * 2f * Math.PI.toFloat()

    fun blob(x: Float, y: Float, r: Float, color: Color, drift: Float, ang: Float) {
        val a = t + ang
        val cx = size.width * (x + drift * kotlin.math.cos(a))
        val cy = size.height * (y + drift * 0.7f * kotlin.math.sin(a * 0.8f))
        val radius = size.width * r * (1f + 0.06f * kotlin.math.sin(a * 1.3f))
        drawCircle(
            Brush.radialGradient(listOf(color, color.copy(alpha = 0f)), center = Offset(cx, cy), radius = radius),
            radius = radius,
            center = Offset(cx, cy),
        )
    }

    // 底色本身就换色：青绿 ↔ 湖蓝 ↔ 紫，12 秒一轮
    val w1 = (0.5f + 0.5f * kotlin.math.sin(t)).toFloat()
    val w2 = (0.5f + 0.5f * kotlin.math.sin(t + 2.1f)).toFloat()
    val c0 = androidx.compose.ui.graphics.lerp(Color(0xFFA9EFD6), Color(0xFFCDE8FF), w1)
    val c1 = androidx.compose.ui.graphics.lerp(Color(0xFF9FC3FF), Color(0xFFD9C6FF), w2)
    val c2 = androidx.compose.ui.graphics.lerp(Color(0xFFCBBFFA), Color(0xFF9FE7F2), w1)
    drawRect(
        Brush.linearGradient(
            0f to c0, 0.5f to c1, 1f to c2,
            start = Offset(size.width * (0.1f * kotlin.math.sin(t)), 0f),
            end = Offset(size.width * (1f - 0.1f * kotlin.math.sin(t)), size.height),
        )
    )

    // 三个光斑大范围漂移，半径也跟着呼吸
    blob(0.20f, 0.15f, 0.90f, Color(0x66FFF3D0), 0.16f, 0f)
    blob(0.90f, 0.85f, 0.80f, Color(0x4DFFC3E4), 0.18f, 2.4f)
    blob(0.55f, 0.50f, 0.70f, Color(0x40B9A8FF), 0.14f, 4.4f)

    // 大字水印：跟着背景一起漂 —— 位置、角度、明暗都由 phase 驱动，
    // 被 28f 模糊之后是"隐约一层字在流动"，而不是钉死在某个位置。
    val nativeCanvas = drawContext.canvas.nativeCanvas
    val wmSize = size.width * 0.34f
    val wx = size.width * (0.50f + 0.07f * kotlin.math.sin(t * 1.1f))
    val wy = size.height * (0.40f + 0.05f * kotlin.math.cos(t * 0.9f))
    val wRot = -11f + 5f * kotlin.math.sin(t * 0.7f)
    val wAlpha = (0x3A + 0x1E * (0.5f + 0.5f * kotlin.math.sin(t * 1.3f))).toInt()
    nativeCanvas.save()
    nativeCanvas.rotate(wRot, wx, wy)
    watermarkPaint.textSize = wmSize
    watermarkPaint.color = (wAlpha shl 24) or 0x00FFFFFF
    nativeCanvas.drawText("酷安璃do", wx, wy, watermarkPaint)
    // 错开的第二层，横向偏移，跟着一起动：两层叠出厚度
    watermarkPaint.textSize = wmSize * 0.62f
    watermarkPaint.color = ((wAlpha * 2 / 3) shl 24) or 0x00FFFFFF
    nativeCanvas.drawText("酷安璃do", wx + size.width * 0.05f, wy + wmSize * 0.72f, watermarkPaint)
    nativeCanvas.restore()

}

@Composable
private fun GlassPill(
    label: String,
    backdrop: com.kyant.backdrop.Backdrop,
    shape: com.kyant.shapes.RoundedRectangularShape,
    onClick: (() -> Unit)?,
) {
    Box(
        Modifier
            .fillMaxWidth(0.66f)
            .height(56.dp)
            .then(if (onClick != null) Modifier.glassClickable(onClick) else Modifier)
            .drawBackdrop(
                backdrop = backdrop,
                shape = { shape },
                effects = {
                    vibrancy()
                    blur(2.dp.toPx())
                    lens(12.dp.toPx(), 24.dp.toPx())
                },
                highlight = { Highlight.Default.copy(alpha = 0.5f) },
                shadow = { Shadow.Default },
                innerShadow = { InnerShadow.Default },
                // 透明玻璃：只叠一层很淡的白，主色交给背景本身
                onDrawSurface = { drawRect(Color.White.copy(alpha = 0.18f)) },
            ),
        contentAlignment = Alignment.Center,
    ) {
        Text(label, color = Color(0xFF111114), fontSize = 16.sp, fontWeight = FontWeight.SemiBold)
    }
}

/** 背景层：渐变 + 半模糊 + 供 drawBackdrop 采样。首页与标定页共用。 */
@Composable
internal fun VividBackdropLayer(backdrop: com.kyant.backdrop.backdrops.LayerBackdrop) {
    // 24 秒一轮，慢到不抢注意力，但玻璃里能看出颜色在走
    val phaseState = androidx.compose.animation.core.rememberInfiniteTransition(label = "backdrop")
        .animateFloat(
            initialValue = 0f,
            targetValue = 1f,
            animationSpec = androidx.compose.animation.core.infiniteRepeatable(
                animation = androidx.compose.animation.core.tween(
                    durationMillis = 12_000,
                    easing = androidx.compose.animation.core.LinearEasing,
                ),
                repeatMode = androidx.compose.animation.core.RepeatMode.Restart,
            ),
            label = "phase",
        )
    val phase = phaseState.value
    Box(
        Modifier
            .fillMaxSize()
            .layerBackdrop(backdrop)
            .background(Color.White)
            .drawBehind { drawVividBackdrop(phase) }
            .graphicsLayer {
                renderEffect = android.graphics.RenderEffect
                    .createBlurEffect(28f, 28f, android.graphics.Shader.TileMode.CLAMP)
                    .asComposeRenderEffect()
            }
    )
}
