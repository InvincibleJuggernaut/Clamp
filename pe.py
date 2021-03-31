import os
import pefile

def extract(path):
    pe = pefile.PE(path, fast_load=True)
    data = []
    data.append(pe.OPTIONAL_HEADER.DllCharacteristics)
    data.append(pe.FILE_HEADER.Machine)
    #entropy = list(map(lambda x:x.get_entropy(), pe.sections))
    #data.append(statistics.mean(entropy))
    data.append(max(entropy))
    data.append(pe.FILE_HEADER.Characteristics)
    data.append(pe.OPTIONAL_HEADER.Subsystem)
    data.append(pe.OPTIONAL_HEADER.ImageBase)
    data.append(pe.OPTIONAL_HEADER.MajorSubsystemVersion)
    data.append(pe.FILE_HEADER.SizeOfOptionalHeader)
    data.append(pe.OPTIONAL_HEADER.MajorOperatingSystemVersion)
    print(data)