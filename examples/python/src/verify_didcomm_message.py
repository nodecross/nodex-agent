import json
from platform_os import is_windows


if is_windows():
    from request import post
else:
    from sock import post


# PLEASE PASTE BELOW THE RESPONSE FROM "generate_didcomm_message.py".
message = {
    "ciphertext": "4odtWoPMVVRPojKklt5Is1F_zhVX5PgQvuIsYs67FjrCN8YMNa37JuWjeZllh_Y5wh8Zfh_pQ_b-W31AimIbn_PV_EtGug8NWVWhRGqFdXGS221yg1dZjyunje-y6v-PH4tOvzG-QJqxMh_1vvHRMOYwyekG1rsSPHoZEuzYouRwiIVoTllBMZxN0Aiqmi4AnLeJ5yezJGhEkueqV_7zxTdbkdPhAkf6r6jgAtazGRRQAT4-j__PMOSsL7QGUm1M2T7imxsTln7i25YtnnAVPIhjUfH5RgpeHFU3SYx4QyxK4HvDAmvTcXIa3OBNGrP1sXaEXFo8nLEFyFHJXJOa6nZOW-4c98Hl5pCYcQMP87hjfGrnPjlpKlybjQb69vS-WeERKUdblasAm2ItXseQpW3FThmtnmP7dHs6iW_442hCyAMOAa1iXSS97pp6rbslOr2yjAQ1NyvwgJxCVDoDb5wd8em_69-vV3H-VatuxRZZpEmRtrkHs5p_F199xjVlwJtM6r0W0T4KCNz89zapMcjtj2L_HF_FXFK-n-cjfoky6Qtc9kNCtHHz1xOZ3lt-dKowzDtlqdmNwroGtYdv3tZruPF2r6FpBPq6KpDpmznu8OdapNFZtdXb37v7RBKZBko6nnVx3y5_3tifHSRMXD-VLxqCzA2RDknHEXptfenpbmxt842CeLeC07pzNCUjviljI7mU2ocrRRgcsRZ7wdqhTWLKt46Pn_MSFKwn7EdnAxUvw-CnU0C2bEdWc9v-0_sSufETFUmAth6ThgxXwcNyBwdpgi3UOkZULeMMBORCgTqYRYPgd9o6wHWVCZJTURbq9PQINTWtsZniJjFk-MunNQy8qVQ87y9gxaF2nPJ9I0QYAUZCZwpB3F3vK1XIt6L160wWqMWnLM1RbMuv1OfyJd5PgGbfWeJmbcaI-06D9rf33tjUcuU_HRYCpWqRFGJyM8QE7gNDtDNHkmKCXeXt6QQeeKj-vQlDpc-dRbV2WVb-kxmoWHrtRRMZw7ekfi19hwxgOrzueIY_wehvMF5hTWkKlbXbnDPs-PhCbnHCiFZuWyM9ozR2xK5orIVLjwaenZbFKx-cFZxWBgvgJ3YlUKXlwqESbvGzBsljK_gYIOiHhXpewxmLiTT0c9988kn4xwLVukH4Y7IfjlVEVMFtr9weIFEh9hGjm25pjJrWFwm8eqSErq9bA7-eam-ZqcAGgvfk6n2sKMCa7APgT0cJJPJ8dtNT4UZiSi9skKfk4xDnJI9bvgg2mlseRPz6FpfXSr9EelMpIkoukexoCzjHUZCdBUEDCfukBFOO5mYIgQM0gMRggg5jP6eCsGazqxlBMZFEzHQX2R5wGfKqO2x4Yrj6lvIrYQIZMxl_cRT8_e_L3q-ybfyjJ9H3766wUowXjEl7ymb4J-OCbj0vFBHSQj0ITFb0cd_ofau6Bbq0vIYDlAbVal-JK8NJk5x-t_CPnP8hFy84NycQ0Hv0lmUq-DlMYn2tgfxVOJSNoiP1N5Qc3P0H7jUtoT2Z4sKO49e5f-F7IvgWOclUSf7F2dBMfFMjhZ8xCmlGB4sfwFRZks1tKthB7Mnk5r89H7pYWhhq6wPkx2z006DGeSjOPsTNLl1pIFOEeG3kUj_V4ha855FkD6u_cc4WXJGEQ_uT4d2EfoQ4-PxwoMzAhJH4yQRHdFWFnmnJ7tx1vM0qw0kqZM5vTjXZIh82DvrG9of3u41EfroPuxYHwdBQZxAvrDiDGofWc_uIXd7I01RGFHnR5VPtpIZAHECrPO48--DH3Tcux6e_3FGz1VFDHQfOlvt8ifIb1M38TJQFE1xkNBmq2nj0ya8444accNoPjXYOAhbTFeyv-WJfOPfnZasSjTBg0cBG5Dxlj1dr717R_3_BqCDJeX7i7PG-MehQ-u7XFdIvk4TNNOW5Bb_vOFgwycFEOCA2199qkODbdkOwqgMlxZLrFke011evsHA4eBx0-jYAY8N9uWOGKaPtWH-ScpZFcjQEJPV7iT4Xhby5xZDCn7b2PWJiSHzU3cjE0NezA6bV7tNMkNehfchD4MHfe3mOw2A4Tmls_5CLB4pnqLGJX7cCTdNzd2Y5oAEc0VsrcsX1XbmpQtRYRhFx-HbZ-88Do94XGrOR2c1IplKnB2xT88HSS_GBGqDqtDS-LdOeLXZnd1ytK85w6NUDpP7KvLpc9fQKASmq-oFqnVh2FXPQf8l9R3rf-0J7FogYyHMtkmRCbXIKHEDSx7bwFQgnL6mq0YLO7MLGrkhS1SnHre4m5LqWOPHgOCzp-pmUe89_D3jyt0MM8vxk9Y1MK4TrzZwqU0w8Mhz4fU_hUrznFZwWHOi9fBxIlNpaR-Dr6o2rAO7yra2QxtBQ0Hc4ImxsSgI3uD5GqFXqZTgTFxzNaondhDjZYSPdK7qeSqaDAs9wIjJCQhpEKWQabUqlZ2K-sg_ohLJqNtwQ7WD_wU_nApBxsj7fS2tnmPRTV57VoImwpLGQOFF3IJpIq6SNgtvXWuefDnCD-s00zT0qpPJlUX5_8U9kxFqJZYwbfyF2NEZFpIsGBZ-HZjTnkL2mx398CNW6SphTsA_1zjuWgxEXlqI--8iePPDzSqr5S8zaZUmSVmx4K53ZCPsU8oKz5Ud6GBMmcpXkW1r84MwRs0GsnQS70lBUtw9DLwacKyQNM5nfepSas6X-JbG4EeNp_EC2g4IYiLqEcuNLkW_pVFMAuofVQFpwZv41_QhshJ2BH8jjA48Fde49e7XRaedeutpqp-r2hTn68J3GmCA68HlU6ZbCGUTjyskWBebr9N6Qvm5QY2J0lAXIUcI7KApDgiYQs3teFpQ5vCGmMBOP93YFMGOBH649OnvQvmBy0jP3RBPJ30tOnSw5-K0fndMpSY1GXh8MtwJD62kxyKqniCfTbBnFRXV8N4WcvA6mk6MNMs14eeCTr8w7H9rDwUofG3QFLjaNonSLIv69DZJGCV7M6v6pME7WiSNJeaGEnFNJcdFLQZyb67kn4LdayoYHyRgELw9VCs-U13UoBvyOv_Sl7xjLtyLUegJWh7Ius0fT-xe8ekLHDKxr2REJaT8sAAyXzmSSyrav5LIrr4RPGBrYbuzY-HL5sabj8o_-jRnXpbxJ5EAZLL0-UMdklsgy7Ks_G8lhv-AzROjKLdtza2cd9QG9HEFT3whlpbgmDyqu1ERRETzAvsd0VkS3hvKCgPk87SIm96U6UogsCHY-nc3KcH7THhf4TDq5GdZl0Bx178LKkbLc3Ffksjbei4IVfibito3C_ug6vtsWDoK1TkfXMTWO4HPQ5L7bDeJ-6g7wwEMVYNdjPO7HU-Cd2IaO4wXcpAeacJ-McA_i-zBFl9j7qHXMjcp_AkUZRM52COmE__35-B_neEaG7DeHE-caufpiEatCYtTIU7OAFfvw5Oo05LxKLEPVeDsCKQsfl5DLsEw-khNOE2KG0PAZqb85ELgHv2rkX1Tv5Iwr-ETH-tGow01E4QVjQpqNr2RzQ1PgyBIN896FtnT_Y42bdJNELI8_LsquKUjACBq_0fDdqMqyoHhzF8zpv6E-YqNW08HwKg",
    "iv": "8Yx4LzZPQxGMtkzK6SsdCQG57n_FT0Rj",
    "protected": "eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIiwiZW5jIjoiWEMyMFAiLCJraWQiOiJmc04tdDNqYW1DM2FobkpGNkpBb1p4V0ZXQi1ZaGtxTVVDeGlnak1TVndZIiwic2tpZCI6ImRpZDpub2RleDp0ZXN0OkVpRDlhUVlOVUpNZGdqZVFldERqNTZMTnpSNlNkd2h1WEdGYWx2STNndWdQSFEiLCJhbGciOiJFQ0RILTFQVStYQzIwUEtXIn0",
    "recipients": [
        {
            "encrypted_key": "S-W4UEGIyMrbBddIjkKdjf1W7ggReOBNN0GUmPmxF0Y",
            "header": {
                "alg": "ECDH-1PU+XC20PKW",
                "epk": {
                    "crv": "X25519",
                    "kty": "OKP",
                    "x": "lOWaS4Pr0CgdzjWlZp6MABJPOraolO4qg6DB_IuP_kA",
                },
                "iv": "ZJkeAxXYJ2TCagOWUK4nl5vCOOuxKzK2",
                "key_ops": [],
                "kid": "did:nodex:test:DummyDummyDummyDummyDummyDummyDummyDummyDummyD",
                "tag": "mqkx9V8kKAvT-OvwGoJS6Q",
            },
        }
    ],
    "tag": "LI_BTLTvId9bYwsF_XJmDA",
}


payload = {
    "message": json.dumps(message),
}

json_response = post("/verify-didcomm-message", payload)

print("The response is as follows.\n")
print(json_response)
