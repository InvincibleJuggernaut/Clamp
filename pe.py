import os
import pefile
import pandas as pd

def extract(path):
    pe = pefile.PE(path, fast_load=True)
    data = []
    entropy = list(map(lambda x:x.get_entropy(), pe.sections))
    SectionsMinEntropy = min(entropy)
    SectionsMaxEntropy = max(entropy)
    data.append(pe.OPTIONAL_HEADER.DllCharacteristics)
    data.append(pe.FILE_HEADER.Characteristics)
    data.append(pe.FILE_HEADER.Machine)
    data.append(pe.OPTIONAL_HEADER.ImageBase)
    data.append('0')
    data.append(SectionsMaxEntropy) 
    data.append(pe.OPTIONAL_HEADER.Subsystem)
    data.append(pe.FILE_HEADER.SizeOfOptionalHeader)
    data.append(pe.OPTIONAL_HEADER.MajorSubsystemVersion)
    data.append(SectionsMinEntropy)    
    data.append(pe.OPTIONAL_HEADER.MajorOperatingSystemVersion)
    attributes =[]
    attributes.append(data)
    return pd.DataFrame(attributes)

