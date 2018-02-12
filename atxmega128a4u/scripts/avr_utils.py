def avr_get_register_pairs():
    rpairs = dict()

    for i in range(1, 33, 2):
        rpairs.update({"r%d" % i: "r%d" % (i-1)})

    rpairs.update({
        'XH': 'XL',
        'YH': 'YL',
        'ZH': 'ZL'
    })

    return rpairs


