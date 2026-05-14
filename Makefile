TARGET = iphone:clang:latest:14.0
ARCHS = arm64 arm64e
INSTALL_TARGET_PROCESSES = mediaserverd SpringBoard
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = aaa-vcam125-bypass

aaa-vcam125-bypass_FILES      = Tweak.xm
aaa-vcam125-bypass_LDFLAGS    = -Wl,-x -Wl,-S -lsubstrate
aaa-vcam125-bypass_FRAMEWORKS = Foundation Security CoreVideo VideoToolbox
aaa-vcam125-bypass_CFLAGS     = -fobjc-arc -Wno-deprecated-declarations -Wno-unguarded-availability-new -O2

include $(THEOS_MAKE_PATH)/tweak.mk
