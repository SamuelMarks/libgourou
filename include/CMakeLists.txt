get_filename_component(DIRNAME "${CMAKE_CURRENT_SOURCE_DIR}" NAME)
set(LIBRARY_NAME "${PROJECT_NAME}_${DIRNAME}")

set(Header_Files
        "Base64.h"
        "bytearray.h"
        "device.h"
        "drmprocessorclient.h"
        "fulfillment_item.h"
        "libgourou.h"
        "libgourou_common.h"
        "libgourou_log.h"
        "loan_token.h"
        "user.h"
)
source_group("Header Files" FILES "${Header_Files}")

add_library("${LIBRARY_NAME}" INTERFACE "${Header_Files}")
find_package(pugixml CONFIG REQUIRED)
target_link_libraries(
        "${LIBRARY_NAME}"
        INTERFACE
        "${PROJECT_NAME}_compiler_flags"
        "pugixml"
        "pugixml::static"
        "pugixml::pugixml"
)

include(GNUInstallDirs)
target_include_directories(
        "${LIBRARY_NAME}"
        INTERFACE
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>"
        "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}>"
        "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
)

# setup the version numbering
set_property(TARGET "${LIBRARY_NAME}" PROPERTY VERSION "${${PROJECT_NAME}_VERSION}")
set_property(TARGET "${LIBRARY_NAME}" PROPERTY SOVERSION "${${PROJECT_NAME}_VERSION_MAJOR}")

# install rules
install(FILES ${Header_Files}
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")
