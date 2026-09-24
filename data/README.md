# Datasets

## `urls.csv`

A small, hand-built set of labelled URLs (`url,label`; `0` = legitimate,
`1` = phishing) used to train and evaluate the phishing-URL classifier.

It is **synthetic and intentionally small** — a demonstration of the feature
extraction and Naive Bayes pipeline, not a benchmark. The phishing rows use
patterns common in real phishing (IP-address hosts, `@` in the URL, many
hyphens and subdomains, brand look-alikes, suspicious tokens, plain HTTP); the
legitimate rows are well-known HTTPS sites, some of which deliberately contain
tokens like `login` so the model must weigh several features rather than one.

A production classifier would train on a large, labelled corpus such as the
UCI "Phishing Websites" dataset or PhishTank feeds, with a proper held-out
test set.
