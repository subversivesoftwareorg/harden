import AppKit

/// Renders the Harden anvil icon as an NSImage at any requested size.
///
/// The icon depicts a stylized anvil in steel blue and silver tones with
/// a subtle spark detail — evoking "hardening" as in tempering metal.
func makeHardenIcon(size: CGFloat) -> NSImage {
    NSImage(size: NSSize(width: size, height: size), flipped: true) { rect in
        guard let ctx = NSGraphicsContext.current?.cgContext else { return false }
        let w = rect.width
        let h = rect.height

        // ── Background: dark steel ──────────────────────────────────
        ctx.setFillColor(CGColor(red: 0.08, green: 0.10, blue: 0.14, alpha: 1.0))
        let bgRadius = w * 0.18
        let bgPath = CGPath(roundedRect: rect, cornerWidth: bgRadius, cornerHeight: bgRadius, transform: nil)
        ctx.addPath(bgPath)
        ctx.fillPath()

        // Color palette
        let steelBlue = CGColor(red: 0.42, green: 0.58, blue: 0.78, alpha: 1.0)
        let silver = CGColor(red: 0.72, green: 0.76, blue: 0.82, alpha: 1.0)
        let brightSilver = CGColor(red: 0.85, green: 0.88, blue: 0.92, alpha: 1.0)
        let sparkColor = CGColor(red: 0.95, green: 0.78, blue: 0.30, alpha: 1.0)
        let sparkGlow = CGColor(red: 0.95, green: 0.78, blue: 0.30, alpha: 0.4)

        // ── Anvil body ──────────────────────────────────────────────
        // The anvil is drawn from top to bottom:
        //   1. Top face (flat striking surface)
        //   2. Waist (narrower middle)
        //   3. Base (wide bottom)

        let cx = w * 0.50
        let scale = w / 512.0  // Design at 512, scale to any size

        // Top face — wide flat surface
        let topY = h * 0.28
        let topW = w * 0.56
        let topH = h * 0.10
        let topRect = CGRect(x: cx - topW / 2, y: topY, width: topW, height: topH)

        // Horn (left extension of top face)
        let hornTipX = cx - topW / 2 - w * 0.12
        let hornTipY = topY + topH * 0.5
        let hornBaseTopX = cx - topW / 2
        let hornBaseTopY = topY
        let hornBaseBotX = cx - topW / 2
        let hornBaseBotY = topY + topH

        ctx.saveGState()
        ctx.setShadow(offset: CGSize(width: 0, height: 2 * scale), blur: 8 * scale, color: steelBlue)

        // Draw horn
        ctx.beginPath()
        ctx.move(to: CGPoint(x: hornTipX, y: hornTipY))
        ctx.addLine(to: CGPoint(x: hornBaseTopX, y: hornBaseTopY))
        ctx.addLine(to: CGPoint(x: hornBaseBotX, y: hornBaseBotY))
        ctx.closePath()
        ctx.setFillColor(silver)
        ctx.fillPath()

        // Draw top face
        let topPath = CGPath(roundedRect: topRect, cornerWidth: 3 * scale, cornerHeight: 3 * scale, transform: nil)
        ctx.addPath(topPath)
        ctx.setFillColor(brightSilver)
        ctx.fillPath()

        // Highlight strip on top face
        let highlightRect = CGRect(x: topRect.minX + 4 * scale, y: topY + 2 * scale, width: topW - 8 * scale, height: 3 * scale)
        ctx.setFillColor(CGColor(red: 0.95, green: 0.96, blue: 0.98, alpha: 0.5))
        ctx.fill(highlightRect)

        ctx.restoreGState()

        // Waist — narrower section connecting top to base
        let waistY = topY + topH
        let waistTopW = topW * 0.75
        let waistBotW = topW * 0.55
        let waistH = h * 0.18

        ctx.beginPath()
        ctx.move(to: CGPoint(x: cx - waistTopW / 2, y: waistY))
        ctx.addLine(to: CGPoint(x: cx + waistTopW / 2, y: waistY))
        ctx.addLine(to: CGPoint(x: cx + waistBotW / 2, y: waistY + waistH))
        ctx.addLine(to: CGPoint(x: cx - waistBotW / 2, y: waistY + waistH))
        ctx.closePath()
        ctx.setFillColor(steelBlue)
        ctx.fillPath()

        // Base — wide bottom platform
        let baseY = waistY + waistH
        let baseW = w * 0.65
        let baseH = h * 0.10
        let baseRect = CGRect(x: cx - baseW / 2, y: baseY, width: baseW, height: baseH)
        let basePath = CGPath(roundedRect: baseRect, cornerWidth: 3 * scale, cornerHeight: 3 * scale, transform: nil)

        ctx.saveGState()
        ctx.setShadow(offset: CGSize(width: 0, height: 3 * scale), blur: 10 * scale, color: CGColor(red: 0, green: 0, blue: 0, alpha: 0.5))
        ctx.addPath(basePath)
        ctx.setFillColor(silver)
        ctx.fillPath()
        ctx.restoreGState()

        // ── Spark details ───────────────────────────────────────────
        // Three small sparks above the striking surface
        let sparkBaseY = topY - h * 0.02
        let sparks: [(dx: CGFloat, dy: CGFloat, len: CGFloat)] = [
            (-0.06, -0.10, 0.07),
            (0.02, -0.14, 0.09),
            (0.10, -0.08, 0.06),
        ]

        ctx.saveGState()
        ctx.setShadow(offset: .zero, blur: 6 * scale, color: sparkGlow)
        ctx.setStrokeColor(sparkColor)
        ctx.setLineCap(.round)
        ctx.setLineWidth(2.5 * scale)

        for spark in sparks {
            let sx = cx + spark.dx * w
            let sy = sparkBaseY + spark.dy * h
            let ey = sy - spark.len * h
            ctx.beginPath()
            ctx.move(to: CGPoint(x: sx, y: sy))
            ctx.addLine(to: CGPoint(x: sx + w * 0.01, y: ey))
            ctx.strokePath()
        }

        // Small spark dots
        let dotSparks: [(dx: CGFloat, dy: CGFloat)] = [
            (-0.10, -0.06),
            (0.07, -0.12),
            (0.14, -0.04),
            (-0.02, -0.16),
        ]
        ctx.setFillColor(sparkColor)
        let dotR = 1.5 * scale
        for dot in dotSparks {
            let dx = cx + dot.dx * w
            let dy = sparkBaseY + dot.dy * h
            ctx.fillEllipse(in: CGRect(x: dx - dotR, y: dy - dotR, width: dotR * 2, height: dotR * 2))
        }

        ctx.restoreGState()

        return true
    }
}
