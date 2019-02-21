#!/usr/bin/python

import json, sys, getopt, os
import nltk
from nltk import FreqDist

def usage():
  print("Usage: %s [train.json] [classify.json]" % sys.argv[0])
  sys.exit()

word_bag = []

def getFeatureList(urlData):
  records = []
  classifiers = []
  for record in urlData:
    arecord = []
    arecord.append(record["domain_age_days"])
    arecord.append(record["url_len"])
    arecord.append(record["host_len"])
    arecord.append(record["tld"])
    arecord.append(record["url"])
    arecord.append(record["alexa_rank"])
    arecord.append(record["query"])
    arecord.append(record["host"])
    arecord.append(record["registered_domain"])
    arecord.append(record["file_extension"])
    if record["malicious_url"] == 1:
      classifiers.append(unicode('pos'))
    if record["malicious_url"] == 0:
      classifiers.append(unicode('neg'))
    try:
      for i in record["ips"]:
        arecord.append(i["geo"])
        arecord.append(i["ip"])
    except:
      pass
    for i in record["domain_tokens"]:
      arecord.append(i)
    map(str,arecord)
    records.append(arecord)
    word_bag.extend(arecord)
  return records, classifiers

def getFeatures(records,bag_of_words):
  features = []
  for record in records:
    feature = {}
    for word in bag_of_words:
      feature['contains({})'.format(word)] = (word in record)
    features.append(feature)
  return features

def main(argv):

  trainingFile = sys.argv[1]
  classifyFile = sys.argv[2]
  if len(argv) != 3:
      usage()
  try:
    corpus = open(trainingFile)
    classify = open(classifyFile)
  except:
    usage()

  urldata = json.load(corpus, encoding="latin-1")
  classifydata = json.load(classify, encoding="latin-1")

  trainRecords, classifiers = getFeatureList(urldata)
  liveRecords, nullclassifiers = getFeatureList(classifydata)

  bag_of_words = FreqDist(word_bag)

  practice_features = getFeatures(trainRecords, set([i[0] for i in FreqDist(bag_of_words).most_common(2000)])) # This bag may be too big!
  real_features = getFeatures(liveRecords, set([i[0] for i in FreqDist(bag_of_words).most_common(2000)]))
  train_set = zip(practice_features,classifiers)
  classifier = nltk.NaiveBayesClassifier.train(train_set)

  results = classifier.classify_many(real_features)
  neg = 0
  pos = 0
  for i in results:
    if i =='neg':
      neg+=1
    if i == 'pos':
      pos+=1
  print("positive %d %f percent" %(pos, 100 * pos/float(pos + neg)))
  print("negative %d %f percent" %(neg, 100 * neg/float(pos+neg)))



  corpus.close()

if __name__ == '__main__':
    main(sys.argv)
