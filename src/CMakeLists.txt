set(LIBRARY_NAME "libgourou")

set(Source_Files
        "bytearray.cpp"
        "bytearray.cpp"
        "device.cpp"
        "fulfillment_item.cpp"
        "libgourou.cpp"
        "loan_token.cpp"
        "user.cpp"
        )
source_group("Source Files" FILES "${Source_Files}")

add_library("${LIBRARY_NAME}" "${Source_Files}")

find_package(pugixml CONFIG REQUIRED)
target_link_libraries(
        "${LIBRARY_NAME}"
        PRIVATE
        pugixml
        pugixml::static
        pugixml::pugixml
        "${PROJECT_NAME}_include"
)
if (MSVC)
  set_property(TARGET "${LIBRARY_NAME}" APPEND_STRING PROPERTY LINK_FLAGS " /NODEFAULTLIB:MSVCRTD")
endif (MSVC)

target_compile_definitions(
        "${LIBRARY_NAME}"
        PUBLIC
        LIBGOUROU_VERSION="${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}${PROJECT_VERSION_TWEAK}"
)

target_link_libraries(
        "${LIBRARY_NAME}"
        PRIVATE
        "${PROJECT_NAME}_compiler_flags"
)

include(GNUInstallDirs)
include(GenerateExportHeader)
set(_export_file "${CMAKE_BINARY_DIR}/${LIBRARY_NAME}_export.h")
generate_export_header("${LIBRARY_NAME}" EXPORT_FILE_NAME "${_export_file}")

target_include_directories(
        "${LIBRARY_NAME}"
        PUBLIC
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>"
        "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
)

# setup the version numbering
set_property(TARGET "${LIBRARY_NAME}" PROPERTY VERSION "${${PROJECT_NAME}_VERSION}")
set_property(TARGET "${LIBRARY_NAME}" PROPERTY SOVERSION "${${PROJECT_NAME}_VERSION_MAJOR}")

install(FILES "${_export_file}"
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

install(TARGETS "${LIBRARY_NAME}" "${PROJECT_NAME}_utils" "${PROJECT_NAME}_include"
        # TYPE "RUNTIME"
        RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
        LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        COMPONENT           "${PROJECT_NAME}")
