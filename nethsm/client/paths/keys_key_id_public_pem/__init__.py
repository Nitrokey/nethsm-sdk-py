# do not import all endpoints into this module because that uses a lot of memory and stack frames
# if you need the ability to import all endpoints from this module, import them with
# from nethsm.client.apis.paths.keys_key_id_public_pem import KeysKeyIDPublicPem

path = "/keys/{KeyID}/public.pem"