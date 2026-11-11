package com.extractkit.app

import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.graphicsLayer

/**
 * 玻璃上的点击：不要系统 ripple（在白/彩色玻璃上会变成一块突兀的深色），
 * 只做一点点「按下去」的反馈——整体轻微变淡 + 缩一点点。
 */
@Composable
internal fun Modifier.glassClickable(
    onClick: () -> Unit,
    onLongClick: (() -> Unit)? = null,
    enabled: Boolean = true,
): Modifier {
    val source = remember { MutableInteractionSource() }
    val pressed by source.collectIsPressedAsState()
    val gesture = if (onLongClick != null) {
        Modifier.combinedClickable(
            enabled = enabled,
            interactionSource = source,
            indication = null,
            onClick = onClick,
            onLongClick = onLongClick,
        )
    } else {
        Modifier.clickable(
            enabled = enabled,
            interactionSource = source,
            indication = null,
            onClick = onClick,
        )
    }
    return this
        .then(gesture)
        .graphicsLayer {
            alpha = if (pressed) 0.88f else if (enabled) 1f else 0.55f
            val s = if (pressed) 0.988f else 1f
            scaleX = s
            scaleY = s
        }
}
