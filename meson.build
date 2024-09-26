project(
  'efusemem', 'c',
  version : '0.1.1',
  license : 'MIT',
  default_options : [
    'c_std=gnu99',
    'warning_level=3'
  ]
)

version_array = meson.project_version().split('.')
version_data = configuration_data({
  'EFUSEMEM_VERSION_MAJOR' : version_array[0].to_int(),
  'EFUSEMEM_VERSION_MINOR' : version_array[1].to_int(),
  'EFUSEMEM_VERSION_MICRO' : version_array[2].to_int(),
  'EFUSEMEM_VERSION' : meson.project_version()
})

configure_file(
  input : 'src/version.h.in',
  output : 'version.h',
  configuration : version_data
)

deps = []

system_funcs = [
  'getopt',
]

exec = executable(
  meson.project_name(),
  sources : ['src/efusemem.c'],
  dependencies : deps,
  install : true
)
