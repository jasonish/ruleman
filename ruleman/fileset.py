import os
import tarfile
import io

def fileset_from_directory(directory):
    """ Create a fileset from a directory. """
    directory = os.path.realpath(directory)
    files = {}
    for dirpath, dirnames, filenames in os.walk(directory):
        for filename in ["%s/%s" % (dirpath, fn) for fn in filenames]:
            files[filename[len(directory)+1:]] = open(filename).read()
    return files

def fileset_from_archive(filename):
    """ Create a fileset from an archive file.

    Only .tar.gz supported right now.
    """
    files = {}

    # Python 2.6 doesn't support 'with' here.
    tf = tarfile.open(filename)
    for member in [member for member in tf if member.isreg()]:
        files[member.name] = tf.extractfile(member).read()
    tf.close()
    return files
    
