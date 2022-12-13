import mdc_api
def api_surpass():

    for i in range(4000):
        res = mdc_api.mdc_api("5e2bf57d3f40c4b6df69daf1936cb766f832374b4fc0259a7cbff06e2f70f269")
        if res =='Already surpassed the API':
            return
api_surpass()
