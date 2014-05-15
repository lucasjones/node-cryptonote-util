{
    "targets": [
        {
            "target_name": "cryptonote",
            "sources": [
                "src/main.cc",
                "src/cryptonote_core/cryptonote_format_utils.cpp",
                "src/crypto/tree-hash.c",
                "src/crypto/hash.c",
                "src/crypto/keccak.c"
            ],
    		"include_dirs": [
    			"src",
    			"src/contrib/epee/include"
    		],
    		"link_settings": {
    	    	"libraries": [
    	    		"-lboost_system"
    	    	]
    	    },
    		"cflags!": [ "-fno-exceptions", "-fno-rtti" ],
			"cflags_cc!": [ "-fno-exceptions", "-fno-rtti", "-std=c++11", "-frtti" ],
    		"cflags": [
  				"-std=c++11",
  				"-fexceptions",
  				"-frtti"
			]
        }
    ]
}
