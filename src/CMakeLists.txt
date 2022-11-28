get_filename_component(DIRNAME "${CMAKE_CURRENT_SOURCE_DIR}" NAME)
set(LIBRARY_NAME "${PROJECT_NAME_NO_PREFIX}")

set(Source_Files
        "bytearray.cpp"
        "device.cpp"
        "fulfillment_item.cpp"
        "libgourou.cpp"
        "loan_token.cpp"
        "user_drm.cpp"
)
source_group("Source Files" FILES "${Source_Files}")

add_library("${LIBRARY_NAME}" "${Source_Files}")

find_package(updfparser CONFIG REQUIRED)

target_link_libraries(
        "${LIBRARY_NAME}"
        PRIVATE
        "${PROJECT_NAME_NO_PREFIX}_compiler_flags"
        "${PROJECT_NAME_NO_PREFIX}_include"
        "updfparser"
        "updfparser_include"
        "updfparser_compiler_flags"
)

include(GNUInstallDirs)

target_include_directories(
        "${LIBRARY_NAME}"
        INTERFACE
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>"
        "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}>"
        "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
)

include(GenerateExportHeader)
set(_export_file "${CMAKE_BINARY_DIR}/libgourou_export.h")
generate_export_header(
        "${LIBRARY_NAME}"
        BASE_NAME             "LIBGOUROU"
        EXPORT_FILE_NAME      "${_export_file}"
)

# setup the version numbering
set_property(TARGET "${LIBRARY_NAME}" PROPERTY VERSION "${${PROJECT_NAME}_VERSION}")
set_property(TARGET "${LIBRARY_NAME}" PROPERTY SOVERSION "${${PROJECT_NAME}_VERSION_MAJOR}")

# install rules
install(FILES ${_export_file}
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

install(TARGETS
            "${LIBRARY_NAME}"
            "${PROJECT_NAME_NO_PREFIX}_compiler_flags"
            "${PROJECT_NAME_NO_PREFIX}_utils"
            "${PROJECT_NAME_NO_PREFIX}_include"
        EXPORT "${PROJECT_NAME}Targets"
        ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(EXPORT "${PROJECT_NAME}Targets"
        DESTINATION "${CMAKE_INSTALL_DATADIR}/${PROJECT_NAME}")
