# simple-pii-detection
Leverages [Microsoft Presidio](https://microsoft.github.io/presidio/getting_started/ "Microsoft Presidio") to reformat results into JSON format sorted by entity type.

## Instructions
Install python and run the following commands through command line
```
pip install presidio_analyzer
pip install presidio_anonymizer
python -m spacy download en_core_web_lg
```

## pii_detection.py
Simple script that requires you to add the text file you want to analyze into the same folder as *pii_detection.py* and change filename variable to the name of the text file. 1-MB-Test.txt was added into repository for testing. 

Outputs JSON into the console, can copy output into a [JSON viewer](https://jsonviewer.stack.hu/) to review results.

## pii_detection_tika.py
A more complex version of *pii_detection.py*  that leverages Apache Tika, which can extract text from 1000+ file types. Then JSON results will be output into a folder.

You will need to download the [tika server jar file](https://tika.apache.org/download.html), open command line, cd into where jar file is stored, and then run
```
java -jar tika-app-2.8.0.jar
```
Create a folder and store all of the documents that you want to be analyzed and then run the script. Console will display the current file its analyzing. Once complete a new subfolder called **output** will be created in the same folder as the analyzed documents.