import

data = []
with open('~/data/smtp_detector_out.json') as f:
    for line in f:
        data.append(json.loads(line))
