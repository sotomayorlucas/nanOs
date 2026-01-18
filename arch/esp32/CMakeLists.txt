# NanOS ESP32 Component - ESP-IDF CMakeLists.txt
#
# To build:
#   1. Create new ESP-IDF project: idf.py create-project nanos_swarm
#   2. Copy this folder to components/nanos/
#   3. Build: idf.py build
#   4. Flash: idf.py flash monitor

idf_component_register(
    SRCS
        "hal_esp32.c"
        "../../kernel/nanos_embedded.c"
    INCLUDE_DIRS
        "../../include"
    REQUIRES
        esp_wifi
        esp_now
        nvs_flash
        driver
)

# Compile definitions
target_compile_definitions(${COMPONENT_LIB} PUBLIC
    NANOS_PLATFORM_ESP32
)

# Optional features
option(NANOS_ENABLE_DEEP_SLEEP "Enable deep sleep support" ON)
option(NANOS_ENABLE_OTA "Enable OTA updates" OFF)
option(NANOS_DEBUG "Enable debug output" ON)

if(NANOS_ENABLE_DEEP_SLEEP)
    target_compile_definitions(${COMPONENT_LIB} PUBLIC NANOS_DEEP_SLEEP)
endif()

if(NANOS_DEBUG)
    target_compile_definitions(${COMPONENT_LIB} PUBLIC NANOS_DEBUG=1)
endif()
