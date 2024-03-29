# Clamp

<h2>Introduction</h2>

<p> Clamp is a utility program for detecting malicious Windows executable files (.exe or .dll). It makes use of VirusTotal's API as well as a local machine learning model for analyzing the files and producing the final result.
  </p>
  
<h2>Working</h2>

<p> There are three important python scripts as part of Clamp.</p>
<p> The <i>analyzer.py</i> acts as the master controller. It is run by the user and contains code capable of invoking various functions residing in the other three scripts. It calls <i>scanner.py</i> for generating the hash sum of the input file. This hash is then fed to the VirusTotal API using the same file.</p>
<p> If a match is found, <i>scanner.py</i> is called to produce the diagnosis and display it.</p>
<p> If no match is found for the hash, <i>pe.py</i> is called for extracting PE headers from the input file and feed them to the ML model. Then, the final result is displayed.</p>
<br>
 <p align="center">
  <img src="Assets/Program flow.png">
  </p>

<h2>Installation</h2>

<ul>
  <li>Clone this repository using</li>
 
  ```
  git clone https://github.com/InvincibleJuggernaut/Clamp.git
  ```
  
  <li>Enter the downloaded directory using</li>
  
  ```
  cd Clamp
  ```
  <li>Run the script using</li>
 
  ```
  python3 analyzer.py
  ```
  </ul>

<b>Note:</b> <i>This repository doesn't contain the trained machine learning model due to size constraints. Therefore, this program would only work if the file input by the user is recognized by VirusTotal. Incase the file is relatively new and has never been scanned with VirusTotal before, the program wouldn't move forward since it requires the ML model for the diagnosis.</i>

<h2>Demo</h2>

<p align="center">
<img src="Assets/Demo.gif">
</p>

<h2>Remarks</h2>

<p> Modern anti-virus and anti-malware solutions use a combination of mutliple methodologies in order to provide accurate diagnosis. Clamp is quite simply a basic implementation for detecting malware. It can't be used to replace the commercial grade anti-virus engines since it makes use of techniques that are rudimentary as well as not enough to account for all possible threats. </p>
<p>The present-day threats are ever-evolving and there is simply no perfect solution. It's <i>a cat and mouse game</i> with anti-virus vendors having to play catch-up with the malicious actors.
  </p>
  
<h2>License</h2>

<a href="LICENSE">MIT License</a>
