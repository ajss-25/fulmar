import CoreGraphics

struct MenuBarDisplayGeometry: Equatable, Sendable {
    let displayID: UInt32
    let bounds: CGRect
    let menuBarHeight: CGFloat
}

enum StatusItemVisibilityGeometry {
    static func topDisplay(
        containing statusItemFrame: CGRect,
        displays: [MenuBarDisplayGeometry],
        tolerance: CGFloat = 1
    ) -> MenuBarDisplayGeometry? {
        guard statusItemFrame.origin.x.isFinite,
              statusItemFrame.origin.y.isFinite,
              statusItemFrame.width.isFinite,
              statusItemFrame.height.isFinite,
              statusItemFrame.width > 0,
              statusItemFrame.height > 0,
              tolerance.isFinite,
              tolerance >= 0 else { return nil }

        return displays.first { display in
            guard display.bounds.origin.x.isFinite,
                  display.bounds.origin.y.isFinite,
                  display.bounds.width.isFinite,
                  display.bounds.height.isFinite,
                  display.bounds.width > 0,
                  display.bounds.height > 0,
                  display.menuBarHeight.isFinite,
                  display.menuBarHeight > 0 else { return false }

            // Control Center parks unavailable compact items at roughly eight
            // points from a display's left edge. A real status item occupies
            // the status-menu side, not the Apple/app-menu edge. Reject this
            // sentinel even when its coordinates numerically overlap the top
            // band of a display arranged directly below another display.
            let isCompactLeftEdgeParkingFrame = statusItemFrame.width <= 32
                && statusItemFrame.minX >= display.bounds.minX - tolerance
                && statusItemFrame.minX <= display.bounds.minX + 12
            guard !isCompactLeftEdgeParkingFrame else { return false }

            // AX status-item frames and CGDisplayBounds share the Quartz global
            // coordinate system: the top edge is bounds.minY, including for a
            // display arranged above or beside the primary display.
            let horizontal = statusItemFrame.minX >= display.bounds.minX - tolerance
                && statusItemFrame.maxX <= display.bounds.maxX + tolerance
            let bandBottom = display.bounds.minY
                + min(display.menuBarHeight, display.bounds.height)
                + tolerance
            let vertical = statusItemFrame.minY >= display.bounds.minY - tolerance
                && statusItemFrame.maxY <= bandBottom
            return horizontal && vertical
        }
    }

    static func isTopVisible(
        _ statusItemFrame: CGRect,
        displays: [MenuBarDisplayGeometry],
        tolerance: CGFloat = 1
    ) -> Bool {
        topDisplay(
            containing: statusItemFrame,
            displays: displays,
            tolerance: tolerance
        ) != nil
    }
}
