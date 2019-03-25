# -*- coding: utf-8 -*-
"""File containing a Windows Registry plugin to parse the Amcache Hive."""

from __future__ import unicode_literals

import datetime

from dfdatetime import posix_time
from dfdatetime import filetime
from plaso.containers import events
from plaso.containers import time_events
from plaso.lib import definitions
from plaso.parsers.winreg_plugins import interface
from plaso.parsers import winreg


class AmcacheEventData(events.EventData):
  """Amcache event data.

  Attributes:
    full_path (str): full path of file
    sha1 (str): sha1 of file
    productname (str): product name file belongs to
    companyname (str): company name that created product file belongs to
    fileversion (str): version of file
    languagecode (int): language code of file
    filesize (int): size of file in bytes
    filedescription (str): description of file
    linkerts (int): unix timestamp when file was linked
    lastmodifiedts (int): filetime timestamp of last modified datetime of file
    createdtd (int): filetime timestamp of created datetime of file
    programid (str): GUID of entry under Root/Program key file belongs to
  """

  DATA_TYPE = 'windows:registry:amcache'

  def __init__(self):
    """Initializes event data."""
    super(AmcacheEventData, self).__init__(data_type=self.DATA_TYPE)
    self.full_path = None
    self.sha1 = None
    self.productname = None
    self.companyname = None
    self.fileversion = None
    self.languagecode = None
    self.filesize = None
    self.filedescription = None
    self.linkerts = None
    self.lastmodifiedts = None
    self.createdts = None
    self.programid = None

class AmcacheProgramEventData(events.EventData):
  """Amcache programs event data.

  Attributes:
    name (str): name of installed program
    version (str): version of program
    publisher (str): publisher of program
    languagecode (int): languagecode of program
    entrytype (str): type of entry (usually AddRemoveProgram)
    uninstallkey (str): unicode string of uninstall registry key for program
    filepath (str): file path of installed program
    productcode (str): product code of program
    packagecode (str): package code of program
    msiproductcode (str): MSI product code of program
    msipackagecode (str): MSI package code of program
    files (str): list of files belonging to program
    OSatinstall (str): Windows version at install date
  """

  DATA_TYPE = 'windows:registry:amcache:programs'

  def __init__(self):
    """Initializes event data."""
    super(AmcacheProgramEventData, self).__init__(data_type=self.DATA_TYPE)
    self.name = None
    self.version = None
    self.publisher = None
    self.languagecode = None
    self.entrytype = None
    self.uninstallkey = None
    self.filepaths = None
    self.productcode = None
    self.packagecode = None
    self.msiproductcode = None
    self.msipackagecode = None
    self.files = None
    self.OSatinstall = None


class Amcache10Parser(interface.WindowsRegistryPlugin):
  """Amcache Registry plugin for recently run programs."""

  NAME = 'amcache10'
  DESCRIPTION = 'Parser for Amcache Registry entries in Windows 10.'

  URLS = [('https://www.ssi.gouv.fr/uploads/2019/01/'
           'anssi-coriin_2019-analysis_amcache.pdf')]

  _AMCACHE_ROOT_WIN10_FILE_KEY = '\\Root\\InventoryApplicationFile'
  _AMCACHE_ROOT_WIN10_PROGRAM_KEY = '\\Root\\InventoryApplication'

  FILTERS = frozenset([
    interface.WindowsRegistryKeyPathPrefixFilter(
    _AMCACHE_ROOT_WIN10_PROGRAM_KEY),
    interface.WindowsRegistryKeyPathPrefixFilter(
    _AMCACHE_ROOT_WIN10_FILE_KEY)
  ])

  def ExtractEvents(self, parser_mediator, registry_key, **kwargs):
    """Extracts events from a Windows 10 Amcache Registry key.

    Args:
      parser_mediator (ParserMediator): mediates interactions between parsers
          and other components, such as storage and dfvfs.
      registry_key (dfwinreg.WinRegistryKey): Windows Registry key.
    """

    if registry_key.number_of_values == 0:
      return

    if registry_key.path.startswith(self._AMCACHE_ROOT_WIN10_FILE_KEY):
      self._ProcessAMCacheWin10FileKey(parser_mediator, registry_key)
      return

    elif registry_key.path.startswith(self._AMCACHE_ROOT_WIN10_PROGRAM_KEY):
      self._ProcessAMCacheWin10ProgramKey(parser_mediator, registry_key)
      return

  def _ProcessAMCacheWin10FileKey(self, parser_mediator, registry_key):
    """Parses an Amcache Root/InventoryApplicationFile key for Windows 10

    Args:
      parser_mediator (ParserMediator): mediates interactions between parsers
          and other components, such as storage and dfvfs.
      registry_key (dfwinreg.WinRegistryKey): amcache Programs key.
    """
    amcache_datetime = registry_key.last_written_time
    event_data = AmcacheEventData()

    linkdateint = None

    for registry_value in registry_key.GetValues():
      if registry_value.name == "LinkDate":
        linkdatestr = "{:s}".format(registry_value.GetDataAsObject())
        if linkdatestr != '':
          linkdateint = int(datetime.datetime.strptime(linkdatestr, "%m/%d/%Y %H:%M:%S").strftime("%s"))

      elif registry_value.name == "LowerCaseLongPath":
        event_data.full_path = "{:s}".format(registry_value.GetDataAsObject())

      elif registry_value.name == "FileId":
        event_data.sha1 = "{:s}".format(registry_value.GetDataAsObject())[4:]

      elif registry_value.name == "ProductName":
        event_data.productname = "{:s}".format(registry_value.GetDataAsObject())

      elif registry_value.name == "Publisher":
        event_data.companyname = "{:s}".format(registry_value.GetDataAsObject())

      elif registry_value.name == "Version":
        event_data.fileversion = "{:s}".format(registry_value.GetDataAsObject())

      elif registry_value.name == "Language":
        try:
          event_data.languagecode = int("{:d}".format(registry_value.GetDataAsObject()))
        except ValueError:
          event_data.languagecode = int("{:s}".format(registry_value.GetDataAsObject()), 16)

      elif registry_value.name == "Size":
        try:
          event_data.filesize = int("{:d}".format(registry_value.GetDataAsObject()))
        except ValueError:
          event_data.filesize = int("{:s}".format(registry_value.GetDataAsObject()), 16)

      elif registry_value.name == "ProgramId":
        event_data.programid = "{:s}".format(registry_value.GetDataAsObject())

    event = time_events.DateTimeValuesEvent(
      amcache_datetime,
      definitions.TIME_DESCRIPTION_MODIFICATION
    )
    parser_mediator.ProduceEventWithEventData(event, event_data)

    if linkdateint:
      link_event = time_events.DateTimeValuesEvent(
        posix_time.PosixTime(linkdateint),
        definitions.TIME_DESCRIPTION_CREATION
      )
      parser_mediator.ProduceEventWithEventData(link_event, event_data)


  def _ProcessAMCacheWin10ProgramKey(self, parser_mediator, registry_key):
    """Parses an Amcache Root/InventoryApplication key for Windows 10

    Args:
      parser_mediator (ParserMediator): mediates interactions between parsers
          and other components, such as storage and dfvfs.
      registry_key (dfwinreg.WinRegistryKey): amcache Programs key.
    """
    event_data = AmcacheProgramEventData()

    amcache_datetime = registry_key.last_written_time

    installdateint = None

    for registry_value in registry_key.GetValues():
      if registry_value.name == 'InstallDate':
        installdatestr = '{:s}'.format(registry_value.GetDataAsObject())
        if installdatestr != '':
          installdateint = int(datetime.datetime.strptime(installdatestr, '%m/%d/%Y %H:%M:%S').strftime('%s'))

      elif registry_value.name == 'Name':
        event_data.name = '{:s}'.format(registry_value.GetDataAsObject())

      elif registry_value.name == 'Version':
        event_data.version = '{:s}'.format(registry_value.GetDataAsObject())

      elif registry_value.name == 'Publisher':
        event_data.publisher = '{:s}'.format(registry_value.GetDataAsObject())

      elif registry_value.name == 'Language':
        try:
          event_data.languagecode = int('{:d}'.format(registry_value.GetDataAsObject()))
        except ValueError:
          event_data.languagecode = '{:s}'.format(registry_value.GetDataAsObject())

      elif registry_value.name == 'Type':
        event_data.entrytype = '{:s}'.format(registry_value.GetDataAsObject())

      elif registry_value.name == 'RegistryKeyPath':
        event_data.uninstallkey = '{:s}'.format(registry_value.GetDataAsObject())

      elif registry_value.name == 'ManifestPath':
        event_data.filepaths = '{:s}'.format(registry_value.GetDataAsObject())

      elif registry_value.name == 'OSVersionAtInstallTime':
        event_data.OSatinstall = '{:s}'.format(registry_value.GetDataAsObject())

      elif registry_value.name == 'MsiProductCode':
        event_data.msiproductcode = '{:s}'.format(registry_value.GetDataAsObject())

      elif registry_value.name == 'MsiPackageCode':
        event_data.msipackagecode = '{:s}'.format(registry_value.GetDataAsObject())

      elif registry_value.name == 'RootDirPath':
        event_data.files = '{:s}'.format(registry_value.GetDataAsObject())

    event = time_events.DateTimeValuesEvent(
      amcache_datetime,
      definitions.TIME_DESCRIPTION_INSTALLATION)
    parser_mediator.ProduceEventWithEventData(event, event_data)

    if installdateint is not None:
      install_event = time_events.DateTimeValuesEvent(
        posix_time.PosixTime(installdateint),
        definitions.TIME_DESCRIPTION_INSTALLATION
      )
      parser_mediator.ProduceEventWithEventData(install_event, event_data)


class Amcache8Parser(interface.WindowsRegistryPlugin):
  """Amcache Registry plugin for recently run programs."""

  NAME = 'amcache'
  DESCRIPTION = 'Parser for Amcache Registry entries.'

  URLS = [
    ('http://www.swiftforensics.com/2013/12/'
     'amcachehve-in-windows-8-goldmine-for.html')]

  _AMCACHE_ROOT_FILE_KEY = "\\Root\\File"
  _AMCACHE_SHA1 = "101"
  _AMCACHE_DATETIME = "17"
  _AMCACHE_FULL_PATH = "15"
  _AMCACHE_PRODUCTNAME = "0"
  _AMCACHE_COMPANYNAME = "1"
  _AMCACHE_FILEVERSION = "5"
  _AMCACHE_LANGUAGECODE = "3"
  _AMCACHE_FILESIZE = "6"
  _AMCACHE_FILEDESCRIPTION = "c"
  _AMCACHE_LINKERTS = "f"
  _AMCACHE_LASTMODIFIEDTS = "11"
  _AMCACHE_CREATEDTS = "12"
  _AMCACHE_PROGRAMID = "100"

  _AMCACHE_ROOT_PROGRAM_KEY = "\\Root\\Programs"
  _AMCACHE_P_INSTALLDATE = "a"
  _AMCACHE_P_NAME = "0"
  _AMCACHE_P_VERSION = "1"
  _AMCACHE_P_PUBLISHER = "2"
  _AMCACHE_P_LANGUAGECODE = "3"
  _AMCACHE_P_ENTRYTYPE = "6"
  _AMCACHE_P_UNINSTALLKEY = "7"
  _AMCACHE_P_FILEPATHS = "d"
  _AMCACHE_P_PRODUCTCODE = "f"
  _AMCACHE_P_PACKAGECODE = "10"
  _AMCACHE_P_MSIPRODUCTCODE = "11"
  _AMCACHE_P_MSIPACKAGECODE = "12"
  _AMCACHE_P_FILES = "Files"

  FILTERS = frozenset([
    interface.WindowsRegistryKeyPathPrefixFilter(
      _AMCACHE_ROOT_PROGRAM_KEY),
    interface.WindowsRegistryKeyPathPrefixFilter(
      _AMCACHE_ROOT_FILE_KEY)
  ])

  def ExtractEvents(self, parser_mediator, registry_key, **kwargs):
    """Extracts events from a Windows 8 Amcache Registry key.

    Args:
      parser_mediator (ParserMediator): mediates interactions between parsers
          and other components, such as storage and dfvfs.
      registry_key (dfwinreg.WinRegistryKey): Windows Registry key.
    """

    if registry_key.number_of_values == 0:
      return

    if registry_key.path.startswith(self._AMCACHE_ROOT_FILE_KEY):
      self._ProcessAMCacheFileKey(parser_mediator, registry_key)
      return

    elif registry_key.path.startswith(self._AMCACHE_ROOT_PROGRAM_KEY):
      self._ProcessAMCacheProgramKey(parser_mediator, registry_key)
      return

  def _ProcessAMCacheProgramKey(self, parser_mediator, registry_key):
    """Parses an Amcache Root/Programs key for Windows 8

    Args:
      parser_mediator (ParserMediator): mediates interactions between parsers
          and other components, such as storage and dfvfs.
      registry_key (dfwinreg.WinRegistryKey): amcache Programs key.
    """
    amcache_datetime = 0
    event_data = AmcacheProgramEventData()
    for registry_value in registry_key.GetValues():
      if registry_value.name == self._AMCACHE_P_INSTALLDATE:
        amcache_datetime = int('{:d}'.format(registry_value.GetDataAsObject()))

      elif registry_value.name == self._AMCACHE_P_NAME:
        event_data.name = '{:s}'.format(registry_value.GetDataAsObject())

      elif registry_value.name == self._AMCACHE_P_VERSION:
        event_data.version = '{:s}'.format(registry_value.GetDataAsObject())

      elif registry_value.name == self._AMCACHE_P_PUBLISHER:
        event_data.publisher = '{:s}'.format(registry_value.GetDataAsObject())

      elif registry_value.name == self._AMCACHE_P_LANGUAGECODE:
        event_data.languagecode = '{:s}'.format(registry_value.GetDataAsObject())

      elif registry_value.name == self._AMCACHE_P_ENTRYTYPE:
        event_data.entrytype = '{:s}'.format(registry_value.GetDataAsObject())

      elif registry_value.name == self._AMCACHE_P_UNINSTALLKEY:
        event_uninstallkey = registry_value.GetDataAsObject()
        if event_uninstallkey is not None:
          event_data.uninstallkey = '{:s}'.format('\n'.join(event_uninstallkey))

      elif registry_value.name == self._AMCACHE_P_FILEPATHS:
        event_data.filepaths = '{:s}'.format('\n'.join(registry_value.GetDataAsObject()))

      elif registry_value.name == self._AMCACHE_P_PRODUCTCODE:
        event_data.productcode = '{:s}'.format(registry_value.GetDataAsObject())

      elif registry_value.name == self._AMCACHE_P_PACKAGECODE:
        event_data.packagecode = '{:s}'.format(registry_value.GetDataAsObject())

      elif registry_value.name == self._AMCACHE_P_MSIPRODUCTCODE:
        event_data.msiproductcode = '\n'.join(registry_value.GetDataAsObject())

      elif registry_value.name == self._AMCACHE_P_MSIPACKAGECODE:
        event_data.msipackagecode = '\n'.join(registry_value.GetDataAsObject())

      elif registry_value.name == self._AMCACHE_P_FILES:
        event_files = registry_value.GetDataAsObject()
        if event_files is not None:
          event_data.files = '{:s}'.format('\n'.join(event_files))

    event = time_events.DateTimeValuesEvent(
      posix_time.PosixTime(amcache_datetime),
      definitions.TIME_DESCRIPTION_INSTALLATION)
    parser_mediator.ProduceEventWithEventData(event, event_data)

  def _ProcessAMCacheFileKey(self, parser_mediator, registry_key):
    """Parses an Amcache Root/File key for Windows 8

    Args:
      parser_mediator (ParserMediator): mediates interactions between parsers
          and other components, such as storage and dfvfs.
      registry_key (dfwinreg.WinRegistryKey): amcache Programs key.
    """
    amcache_datetime = 0
    event_data = AmcacheEventData()
    for registry_value in registry_key.GetValues():
      if registry_value.name == self._AMCACHE_DATETIME:
        amcache_datetime = int('{:d}'.format(registry_value.GetDataAsObject()))

      elif registry_value.name == self._AMCACHE_FULL_PATH:
        event_data.full_path = '{:s}'.format(registry_value.GetDataAsObject())

      # Strip off the 4 leading zero's from the sha1 hash.
      elif registry_value.name == self._AMCACHE_SHA1:
        event_data.sha1 = '{:s}'.format(registry_value.GetDataAsObject())[4:]

      elif registry_value.name == self._AMCACHE_PRODUCTNAME:
        event_data.productname = '{:s}'.format(registry_value.GetDataAsObject())

      elif registry_value.name == self._AMCACHE_COMPANYNAME:
        event_data.companyname = '{:s}'.format(registry_value.GetDataAsObject())

      elif registry_value.name == self._AMCACHE_FILEVERSION:
        event_data.fileversion = '{:s}'.format(registry_value.GetDataAsObject())

      elif registry_value.name == self._AMCACHE_LANGUAGECODE:
        event_data.languagecode = int('{:d}'.format(registry_value.GetDataAsObject()))

      elif registry_value.name == self._AMCACHE_FILESIZE:
        event_data.filesize = int('{:d}'.format(registry_value.GetDataAsObject()))

      elif registry_value.name == self._AMCACHE_FILEDESCRIPTION:
        event_data.filedescription = '{:s}'.format(registry_value.GetDataAsObject())

      elif registry_value.name == self._AMCACHE_LINKERTS:
        event_data.linkerts = int('{:d}'.format(registry_value.GetDataAsObject()))

      elif registry_value.name == self._AMCACHE_LASTMODIFIEDTS:
        event_data.lastmodifiedts = int('{:d}'.format(registry_value.GetDataAsObject()))

      elif registry_value.name == self._AMCACHE_CREATEDTS:
        event_data.createdts = int('{:d}'.format(registry_value.GetDataAsObject()))

      elif registry_value.name == self._AMCACHE_PROGRAMID:
        event_data.programid = '{:s}'.format(registry_value.GetDataAsObject())

    event = time_events.DateTimeValuesEvent(
      filetime.Filetime(amcache_datetime),
      definitions.TIME_DESCRIPTION_MODIFICATION)
    parser_mediator.ProduceEventWithEventData(event, event_data)

    if event_data.createdts:
      event = time_events.DateTimeValuesEvent(
        filetime.Filetime(event_data.createdts),
        definitions.TIME_DESCRIPTION_CREATION)
      parser_mediator.ProduceEventWithEventData(event, event_data)

    if event_data.lastmodifiedts:
      event = time_events.DateTimeValuesEvent(
        filetime.Filetime(event_data.lastmodifiedts),
        definitions.TIME_DESCRIPTION_MODIFICATION)
      parser_mediator.ProduceEventWithEventData(event, event_data)

    if event_data.linkerts:
      event = time_events.DateTimeValuesEvent(
        posix_time.PosixTime(event_data.linkerts),
        definitions.TIME_DESCRIPTION_CHANGE)
      parser_mediator.ProduceEventWithEventData(event, event_data)


winreg.WinRegistryParser.RegisterPlugin(Amcache8Parser)
winreg.WinRegistryParser.RegisterPlugin(Amcache10Parser)
