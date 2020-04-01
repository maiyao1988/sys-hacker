LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := shack-lib


#$(warning "the value of LOCAL_PATH is $(LOCAL_PATH)")

LOCAL_SRC_FILES += $(wildcard $(LOCAL_PATH)/*.cpp)

#$(warning "lc $(LOCAL_SRC_FILES)")

LOCAL_CFLAGS := -Wno-invalid-source-encoding -Wno-return-type-c-linkage
LOCAL_CPPFLAGS	+= -frtti -fexceptions
LOCAL_LDLIBS += -llog
LOCAL_CFLAGS += -fPIC
LOCAL_LDFLAGS += -fPIC

include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := shack
LOCAL_SRC_FILES += $(wildcard $(LOCAL_PATH)/*.cpp)

LOCAL_CPPFLAGS	+= -frtti -fexceptions
LOCAL_LDLIBS += -llog

LOCAL_LDFLAGS += -pie -fPIE
LOCAL_CFLAGS += -pie -fPIE

include $(BUILD_EXECUTABLE)

