# simple-pii-detection

## Instructions
Install python and run the following commands through command line
```
pip install presidio_analyzer
pip install presidio_anonymizer
python -m spacy download en_core_web_lg
```

Add text file you want to analyze into same folder as pii_detection.py and change filename variable as needed. 1-MB-Test.txt added into repository for testing. Outputs JSON into the console, can copy output into a [JSON viewer](https://jsonviewer.stack.hu/) to review results.
