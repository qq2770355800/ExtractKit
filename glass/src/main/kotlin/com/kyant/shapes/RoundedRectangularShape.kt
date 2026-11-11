package com.kyant.shapes

import androidx.compose.ui.geometry.RoundRect
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Outline
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.LayoutDirection

/** 四条边各自的圆角（像素）。 */
class Corners(
    val topLeft: Float,
    val topRight: Float,
    val bottomRight: Float,
    val bottomLeft: Float,
)

/**
 * 与 Kyant shapes 库同名的最小实现：只保留 backdrop 折射需要的那部分
 * （四条独立圆角 + 能 outline 出圆角矩形）。原库 1.2.1 要求 AGP 9.1 / compileSdk 37，
 * 这里用等价语义的本地实现替代。
 */
interface RoundedRectangularShape : Shape {
    fun corners(size: Size, layoutDirection: LayoutDirection, density: Density): Corners
}

/** 圆角恒为 [radiusPx]（像素，调用方自己乘 density）。 */
class RoundedRectShape(private val radiusPx: Float) : RoundedRectangularShape {

    override fun corners(size: Size, layoutDirection: LayoutDirection, density: Density): Corners {
        val v = radiusPx.coerceAtMost(size.minDimension / 2f)
        return Corners(v, v, v, v)
    }

    override fun createOutline(size: Size, layoutDirection: LayoutDirection, density: Density): Outline {
        val v = radiusPx.coerceAtMost(size.minDimension / 2f)
        return Outline.Generic(
            Path().apply {
                addRoundRect(RoundRect(0f, 0f, size.width, size.height, v, v))
            }
        )
    }
}

/** 胶囊：圆角恒为短边的一半。 */
class CapsuleShape : RoundedRectangularShape {
    override fun corners(size: Size, layoutDirection: LayoutDirection, density: Density): Corners {
        val v = size.minDimension / 2f
        return Corners(v, v, v, v)
    }

    override fun createOutline(size: Size, layoutDirection: LayoutDirection, density: Density): Outline {
        val v = size.minDimension / 2f
        return Outline.Generic(
            Path().apply {
                addRoundRect(RoundRect(0f, 0f, size.width, size.height, v, v))
            }
        )
    }
}
