# Machine Learning Based IoT IntrusionDetection System: An MQTT Case Study

This work uses six different machine learning techniques to classify attacks in an MQTT network.

## Dataset Used
The used dataset is published in [IEEE DataPort](https://ieee-dataport.org/open-access/mqtt-internet-things-intrusion-detection-dataset)

````
@data{bhxy-ep04-20,
doi = {10.21227/bhxy-ep04},
url = {http://dx.doi.org/10.21227/bhxy-ep04},
author = {Hanan Hindy; Christos Tachtatzis; Robert Atkinson; Ethan Bayne; Xavier Bellekens },
publisher = {IEEE Dataport},
title = {MQTT Internet of Things Intrusion Detection Dataset},
year = {2020} } 
````

## Citation
```
@article{hindy2020machine,
  title={Machine Learning Based IoT Intrusion Detection System: An MQTT Case Study},
  author={Hindy, Hanan and Bayne, Ethan and Bures, Miroslav and Atkinson, Robert and Tachtatzis, Christos and Bellekens, Xavier},
  journal={arXiv preprint arXiv:2006.15340},
  year={2020}
}
````

# Algorithms Used 
- Logistic Regression
- k-Nearest Neighbours
- Gaussian Naive Bayes
- Decision Trees
- Random Forests
- Support Vector Machine (linear and RBF kernel)


## How to Run it:

```
Clone this repository
Download dataset files and extract them in the same directory
run classification.py --mode [0: packet, 1: unidirectional, 2: bidirectional] --output [output_folder] --verbose [True/False]
```
- The classification outputs are added to the output folder. 
