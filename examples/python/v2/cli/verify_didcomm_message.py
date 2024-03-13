from sock import post

def main():
    # The endpoint and payload you want to send
    endpoint = "/verify-didcomm-message"
    payload = {
        "message": """
            {
              "ciphertext": "ycha9AtTBdFTXjP9zPm0cv85EP89uzBF05hvyKJ08lQ8npw6MES9htmLjyyiFl-rXxIW1lFf2FVGD28Gg0jv65tXWyQX7c0MoDmjF9FgIVwTzzgJ_4aR67U7ncX8T03Ib20cXakJWsrOJp1hzJdFEwkoDRJSszbuA4cCkYzeW2ia9jXsZNig90Q2b_m3kFzXCw20tV_JU68xrfs9OtQHwiAUB9_nuskBvdV-lJeoblT8yV3H1Jz5FjLN7JUOV5NBdBk0aDsO0kQ1eFiqZtj5HlZKDB-uKp52ISf80JTJNCb9uB1c-DnCkJw6-D0kk3f83-3y7GN3LfQYSYpxlrpMDnQVtXll0nCTvakiQOUCqQl0eAFMEXeROe-a4dOz3MRdgENnI1fh2N7GMsuh3pax6PI_ssAH51Ya85h_VtJDc6ZqzHkoLhxGALPBJ1-lONXjXdkdPeq5iiGmvkHXwwq4Spe6KyuLiVwbbSVsCQ-qd2yVTuU01EjEo4YVP3L64bA1alwvbZwPfQTBAFAH3J31_50nYmPb4-DdwlFkivQD3CB_1VWUaTQ_7LYlqY_x05UAcb8pYC2sD3rWfV-U18RmRzThfJ9WiycZHaOCn-sKqfYt2UFH8iFBDxYSjy-0dJ0ZvJ_0j9fdPV5vsVchpF8x5ZLXx9jYyucvW9KtIR2c8kp6BWjG-_2Ht87tBMla1dHFjrXfLuNVw9NBpuLcQHkQ-YCAuR5L-PxrLSI51Tg5xBDwnyhZpH4n0RxOWFfXECWduNCJhpFvBtxjSjaqegrk4AW2QJtaPouKHJ24QtlXlJpIHo5n5iS7kV7CQKl7twXIG8OOaL6dlaqx2nuAb6HZpo2xHkLpG3VlMXGl4Lky9PDTk_LTVyUwLxRa7Y-9dBQfrwr3TaGzERol7e1D-Add2zSSOpVYCnIdnw7aRQvXliyF29E0dSlMlMU5lvhjBBa1ya4tbnwHruWd_ZpXWEQzlbBj1pOA3yKblzJyNTLhdqqv5OERIccg3DNLYx3LpVBzxS1ya7vU3GsaRON6qYvOtcaNw74qo1iHiRTDD_dhal4MQ2AEoyU3Tzx0Okgukel9oLPQ_yM5xYQZxEcuXAXWq6twAWYSZBQ0mmJf1C-P2VcQFvLnSufD88pY9xmpc5cb8salBYr21evRF8fvWxL8-KDMRIBdYh9_gUFhadlzz2Qh_Oqhsorvxrv6TtsES0q8ggsIrDmDwQTiG1A6NMkJv4Y4lEYvFT4TJbMK8opvY3H59hVZbsZcdzRc2Hi8GTw2XB08PdGrvtVZhK97oIbnNv8CmLR-9bcDDwny2mE9FcCHSYwwXQ_yCEMiXyImKzxNvNovm8isnDaqva2uP6ERzB_AEAZboiOIKVfrW0kddR1_xCYg1a0TwazFrgXO-8wekBmAzVdhvcIkSPnZblu8LovR9AN9YPOqLkZonYRaj6eeDS4ww5kb_IVXzumcbIiNOEoqHwZoNGASxnO7HktiWncfpnridPY4nhH9fFhTITZsypCoZY5wGEbtlwZEDs8dcFq1-vB70m5ukvQN9Cr3IcqSUYBGI4jSr1NBESVELKyzbu-yasRjD_C60IlSB9VmNrw232Wno-jYWp0nmAcU43kxM2RY9pkjfQaDEXtDUKrTD2fRXlqrAUnOBPest3xeiK1ztUae8mpU9AyRH8KKLI3seY3Un_25deYCZjMJi3FgQ1gsTdTab5oANgd60vvND7NAZadCLDjkgsxUXykQOF5p4W_sd64DQeFyBVlPmK9mnxPo7vqMrs_rpywm7sRSbB49R1UsopDcZxv2cZmVPyzXSGxbV4T9e65k1XBSSeUaf3FI_itOOcDDIS-ms_D81__Ubs5YO4VyN6oR2KvkJGXHUFaNZybvu2hZhaAoqLqAZDlx6p9jGM_OUOwS-0ttWe2HC4BeMb53zrrg8T6dmizgwqQV0C0AU-q7cdPb0uhOl4nHXcTnQDA2PHUmhhEBGZMeZezzZ-Dnseox5ucit5tsTkV8zSVnYWYKgM3cgJTJhLJ1kLaS_oYFmSIuL3KnPjRgUMWAkS7HCU6b1XALusCWACwo6FC7iUspc6UBMrtbLLE70C2n17DnHWxSyVnZoo2OIUeQsvBivmnGT8SnD77V83jVMgYC6m1lEKTrMQki8y4BtVYtL1CfdHHFYZqhXdNegFMOf_3d4uWpHqxZbQnAQu3mz4LAJzcg3gLKRv1bVGhbajGc4IowCFV4hknRKx4WZanIQrtQ-3Q4_OjbHgxTSQ01uImaS-rPpIWH7HBKFw6PVfmumBZgYiAu8O4IhJFY-_py3MXdVQR-bDw2cqjXiF93Pf7-O8PzMeK6T5XMnoy5eK2LbT0a0QSqOHR9PvpM9xYlLoSUeJ03TfxUUxTekyOarF2ACrAOV41_D4gbBklcYmKhdJ69YXNl6wiuiLuxKLQFy4QWxkEC-jEZe5GOGkFgTN1udA4BrOE03Bt3QSNfglxKmF3HBUyAByoU2Sd2h8fr5aUmSSoA0-u4qSvl_E8ODhqEyKK_9THfj4N8QuhLyyQn2tW0Om0x0d0CTNv_OJI9Y8lvWWuDHQ7jOanujqN5xpDucM_dJJnDGGMylsYAazviLusf4gzR3B49qbV-owmGQS_2gWaXV0N8ubTnD1cYjAbto8TQdLXYO3KwQwLwu5Nsr4UskH7MkQI5eupHXyBPxIkyJRkQqbNJUdwcZj_KRYzqzvyWdnnlyCPQBTOE8TneCFeIrBtcYrYHL8eL12c0HIcZG4O4nCa8chTHzd5te4D8TQdUUFE60nlCVHg6n_lT7fo9kgRfl85Ly1QooXVKZCJUh4TQYE5TPJLQeHNszNnhDuMJ7qTR51xsnmvBrKWuWAei0JwfdFfFTqtSU1TLfxmxmTxYhPT-5bR76GWru1v0MDS4vDjzso3hNcpvM5tJIEpYoM17NLCHlrUkKBaXcKrNVlkrZhAW5hb_yczmNVoHQxodTasFyqDFvmSPTQpvnRm0ynTPyqbTj8rbeCqXobmuFLgHybHVd5lz7JtQ6ooAv2JZaTXA21rq6hT5G63BmCaagMpLziNieH0EILjftQ",
              "iv": "UzE5VwKyQB_7sVgDPcPezLgRY87P2g3d",
              "protected": "eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIiwiZW5jIjoiWEMyMFAiLCJraWQiOiJsYUJEZl9PeENFLTF6aVdMLWJUT093RFZVMUYyNGluTk1kWkhOd1ZxUEFBIiwic2tpZCI6ImRpZDp1bmlkOnRlc3Q6RWlCcHJYcmVNaWJhNGxveWwzcHNYbTBSc0VDZHRsQ2lRSWpNOEc5QnRkUXBsQSIsImFsZyI6IkVDREgtMVBVK1hDMjBQS1cifQ",
              "recipients": [
                {
                  "encrypted_key": "ytXSszSTNkVbZw5PZ_7iHQ1waV4yT27idrAuODWO7IY",
                  "header": {
                    "alg": "ECDH-1PU+XC20PKW",
                    "epk": {
                      "crv": "X25519",
                      "kty": "OKP",
                      "x": "XFRApJksjGAcFGzALqYd5mAE1W5Ja3GHDzU_Cy2jd0Y"
                    },
                    "iv": "qWBwU5xflciNmEZ3SYCJ5ulwKJo9M4hW",
                    "key_ops": [],
                    "kid": "did:nodex:test:EiBprXreMiba4loyl3psXm0RsECdtlCiQIjM8G9BtdQplA",
                    "tag": "zdt-fMYmk_9IDhRuwWqWXw"
                  }
                }
              ],
              "tag": "cp7atcUAXtPgLFRogRxRcA"
            }
        """
    }

    # Send the POST request and print the response
    json_response = post(endpoint, payload)
    print(json_response)

if __name__ == "__main__":
    main()

