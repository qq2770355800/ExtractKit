package com.extractkit.app

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Modifier
import com.kyant.backdrop.backdrops.rememberLayerBackdrop
import androidx.lifecycle.viewmodel.compose.viewModel

class GlassCalibrationActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            val vm: CalibrationModel = viewModel()
            val backdrop = rememberLayerBackdrop()
            Box(Modifier.fillMaxSize()) {
                VividBackdropLayer(backdrop)          // 与首页同一套渐变 + 半模糊
                CalibrationRoute(vm, backdrop)
            }
        }
    }

    @Composable
    private fun CalibrationRoute(vm: CalibrationModel, backdrop: com.kyant.backdrop.backdrops.LayerBackdrop) {
        val pickBoot = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            if (uri != null) vm.analyze(contentResolver, uri)
        }
        val pickProfile = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            if (uri != null) vm.importProfile(contentResolver, uri)
        }

        val intent = vm.shareIntent
        LaunchedEffect(intent) {
            if (intent != null) {
                runCatching { startActivity(intent) }
                vm.shareIntent = null
            }
        }

        // 从「查询固件包」页提取出来的 zip 直接进标定
        LaunchedEffect(Unit) {
            this@GlassCalibrationActivity.intent?.getStringExtra("boot_zip")?.let { p ->
                val f = java.io.File(p)
                if (f.isFile) vm.analyzeZip(contentResolver, f)
            }
        }

        GlassCalibrationScreen(
            backdrop = backdrop,
            model = vm,
            onBack = { finish() },
            onPick = { pickBoot.launch(arrayOf("*/*")) },
            onImport = { pickProfile.launch(arrayOf("*/*")) },
            onSave = { vm.saveProfile() },
            onShare = { vm.shareProfile() },
            onCheck98260 = { vm.runCheck98260() },
            onLeak = { vm.runLeakCheck() },
            onFirmware = { startActivity(Intent(this, FirmwareActivity::class.java)) },
        )
    }
}
