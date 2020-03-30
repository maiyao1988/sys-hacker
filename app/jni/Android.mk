LOCAL_PATH := $(call my-dir)


include $(CLEAR_VARS)
LOCAL_MODULE := rev

#$(warning "the value of LOCAL_PATH is $(LOCAL_PATH)")

LOCAL_SRC_FILES += $(wildcard $(LOCAL_PATH)/Substrate/*.cpp)
LOCAL_SRC_FILES += $(wildcard $(LOCAL_PATH)/Substrate/*.c)
LOCAL_SRC_FILES += $(wildcard $(LOCAL_PATH)/*.cpp)


#$(warning "lc $(LOCAL_SRC_FILES)")

#LOCAL_SRC_FILES := Substrate/SubstrateHook.cpp
#LOCAL_CFLAGS := -fvisibility=hidden -Wno-invalid-source-encoding -Wno-return-type-c-linkage
LOCAL_CFLAGS := -Wno-invalid-source-encoding -Wno-return-type-c-linkage
LOCAL_CPPFLAGS	+= -frtti -fexceptions
LOCAL_LDLIBS += -llog

#LOCAL_CFLAGS +=

#LOCAL_LDFLAGS +=

#LOCAL_CFLAGS += -mllvm -sub

#LOCAL_CFLAGS += -mllvm -bcf

#LOCAL_CFLAGS += -mllvm -fla


include $(BUILD_SHARED_LIBRARY)
