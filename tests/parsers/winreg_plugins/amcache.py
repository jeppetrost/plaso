#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Tests for the Amcache Registry plugin."""

from __future__ import unicode_literals

import unittest

from plaso.parsers import winreg
from plaso.parsers.winreg_plugins import amcache

from tests import test_lib as shared_test_lib
from tests.parsers.winreg_plugins import test_lib


class AmcacheParserTest(test_lib.RegistryPluginTestCase):
  """Tests for the Amcache Registry plugin for Windows 8."""

  @shared_test_lib.skipUnlessHasTestFile(['Amcache.hve-win8'])
  def testParse(self):
    """Tests the Parse function."""

    parser = winreg.WinRegistryParser()
    parser.EnablePlugins([amcache.Amcache8Parser.NAME])
    storage_writer = self._ParseFile(['Amcache.hve-win8'], parser)

    self.assertEqual(storage_writer.number_of_errors, 0)
    self.assertEqual(storage_writer.number_of_events, 2208)

    event_0_expected ={'inode': 581897,
                       'sha1': '82274eef0911a948f91425f5e5b0e730517fe75e',
                       'lastmodifiedts': 131460650153024523,
                       'fileversion': '51.52.0.0',
                       'createdts': 131460650151772758,
                       'data_type': 'windows:registry:amcache',
                       'full_path': 'c:\\users\\user\\appdata\\local\\temp\\chocolatey\\is-f4510.tmp\\idafree50.tmp',
                       'programid': '0006e76af55675279a5fb622dc3bfa54d10400000000',
                       'parser': 'winreg/amcache',
                       'timestamp': 708992537000000,
                       'languagecode': 0,
                       'filedescription': 'Setup/Uninstall',
                       'timestamp_desc': 'Metadata Modification Time',
                       'filesize': 702976,
                       'linkerts': 708992537}



    events = []
    for event in storage_writer.GetSortedEvents():
      if event.parser == '{}/{}'.format(
            winreg.WinRegistryParser.NAME,
            amcache.Amcache8Parser.NAME):
        events.append(event)

    self.assertEqual(len(events), 1179)

    event = events[0]

    self.CheckTimestamp(event.timestamp, '1992-06-19 22:22:17.000000')

    for k, v in event_0_expected.items():
      self.assertEqual(event.__dict__[k], v)


class Amcache10ParserTest(test_lib.RegistryPluginTestCase):
  """Tests for the Amcache Registry plugin for Windows 10."""

  @shared_test_lib.skipUnlessHasTestFile(['Amcache.hve-win10'])
  def testParse(self):
    """Tests the Parse function."""
    parser = winreg.WinRegistryParser()
    parser.EnablePlugins([amcache.Amcache10Parser.NAME])

    storage_writer = self._ParseFile(['Amcache.hve-win10'], parser)

    self.assertEqual(storage_writer.number_of_errors, 0)
    self.assertEqual(storage_writer.number_of_events, 70)

    event_0_expected = {'inode': 582489,
                        'parser': 'winreg/amcache10',
                        'hostname': None,
                        'data_type': 'windows:registry:amcache',
                        'filename': '/home/analyst/plaso/test_data/Amcache.hve-win10',
                        'timestamp': 389082578000000,
                        'filesize': 13312,
                        'languagecode': 1033,
                        'productname': 'microsoft® windows® operating system',
                        'fileversion': '10.0.16299.15 (winbuild.160101.0800)',
                        'sha1': '152c524176f105f26d4bed892a454031fb8b871b',
                        'full_path': 'c:\\windows\\system32\\logonui.exe',
                        'companyname': 'microsoft corporation',
                        'programid': '0000f519feec486de87ed73cb92d3cac802400000000',
                        'timestamp_desc': 'Creation Time',
                        'offset': None}


    events = []
    for event in storage_writer.GetSortedEvents():
      if event.parser == '{}/{}'.format(
          winreg.WinRegistryParser.NAME,
          amcache.Amcache10Parser.NAME):
        events.append(event)

    self.assertEqual(len(events), 44)

    event = events[0]

    self.CheckTimestamp(event.timestamp, '1982-05-01 06:29:38.000000')

    for k, v in event_0_expected.items():
      self.assertEqual(event.__dict__[k], v)


class AmcacheParserNoSystemTest(test_lib.RegistryPluginTestCase):
  @shared_test_lib.skipUnlessHasTestFile(['SYSTEM'])
  def testParseWithSystem(self):
    """Tests the Parse function with a SYSTEM Registry file."""
    parser = winreg.WinRegistryParser()
    parser.EnablePlugins([amcache.Amcache8Parser.NAME,
                          amcache.Amcache10Parser.NAME])

    storage_writer = self._ParseFile(['SYSTEM'], parser)

    self.assertEqual(storage_writer.number_of_errors, 0)
    events8 = []
    events10 = []
    for event in storage_writer.GetSortedEvents():
      if event.parser == '{}/{}'.format(
          winreg.WinRegistryParser.NAME,
          amcache.Amcache8Parser.NAME):
        events8.append(event)
      elif event.parser == '{}/{}'.format(
          winreg.WinRegistryParser.NAME,
          amcache.Amcache10Parser.NAME):
        events10.append(event)
    self.assertEqual(len(events8), 0)
    self.assertEqual(len(events10), 0)


if __name__ == '__main__':
  unittest.main()
