// imagemagick plugins
const std = @import("std");

pub const c = @cImport({
    @cInclude("GraphicsMagick/wand/magick_wand.h");
});

pub const MagickContext = struct {
    wand: *c.MagickWand,

    pub fn init() !MagickContext {
        c.InitializeMagick(null);

        var wand = c.NewMagickWand();
        if (wand == null) return error.WandCreateFail;

        return MagickContext{
            .wand = wand.?,
        };
    }

    pub fn deinit(self: *MagickContext) void {
        _ = c.DestroyMagickWand(self.wand);
        c.DestroyMagick();
    }
};

pub fn loadImage(path: [:0]const u8) !MagickContext {
    var mctx = try MagickContext.init();
    errdefer mctx.deinit();

    if (c.MagickReadImage(mctx.wand, path) != 1) {
        return error.MagickReadFail;
    }

    return mctx;
}
