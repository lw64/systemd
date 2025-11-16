# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_IMPORTD') != 1
        subdir_done()
endif

add_languages('rust')
rust = import('unstable-rust')

pull_bindgen = rust.bindgen(
  input : 'pull-varlink.h',
  output : 'pull-varlink.rs',
  #include_directories : 'include',
)

systemd_delta_pull_sources = structured_sources(
        [
                'pull.rs',
                pull_bindgen,
        ],
)

systemd_delta_pull_c_sources = files(
        'pull-varlink.c',
)

executables += [
        libexec_template + {
                'name' : 'systemd-delta-pull',
                'public' : true,
                'sources' : [
                        systemd_delta_pull_sources,
                        systemd_delta_pull_c_sources
                ],
                'structured' : true,
                #'override_options' : {'rust_dynamic_std': true},
        }
]
