#
# Software Name : abcdesktop.io
# Version: 0.2
# SPDX-FileCopyrightText: Copyright (c) 2020-2021 Orange
# SPDX-License-Identifier: GPL-2.0-only
#
# This software is distributed under the GNU General Public License v2.0 only
# see the "license.txt" file for more details.
#
# Author: abcdesktop.io team
# Software description: cloud native desktop service
#

def detectLocale(acceptLanguageHeader,supportedLocales=(),defaultLocale='en_US'):
    if not acceptLanguageHeader: 
        return defaultLocale

    acceptedLocales = [lq[0] for lq in parseAcceptLanguage(acceptLanguageHeader)]
    return resolveLocale(acceptedLocales, supportedLocales, defaultLocale)


def resolveLocale(acceptedLocales,supportedLocales=(),defaultLocale='en_US'):
    for locale in acceptedLocales:
        supportedLocale = matchLocale(locale,supportedLocales)
        if supportedLocale: 
            return supportedLocale

    return defaultLocale


def parseAcceptLanguage(acceptLanguageHeader):
    languages = acceptLanguageHeader.split(",")
    l_q_pairs = []
    for language in languages:        
        quality = 1
        lq = language.split(";",1)
        if len(lq)>1:
            language = lq[0]
            try:
                quality = float(lq[1].split("=")[1])
            except Exception:                
                pass # don't care nothing to do

        language = language.strip().replace('-','_')
        l_q_pairs.append((language, quality))
        l_q_pairs.sort(key=lambda x: x[1], reverse=True)

    return l_q_pairs


def matchLocale(locale,supportedLocales):
    if not len(supportedLocales):
        return None

    if locale=='*':
        return supportedLocales[0]

    if locale in supportedLocales:
        return locale

    locale = locale.split('_',1)[0]

    locale_loc = locale + '_' + locale.upper()
    if locale_loc in supportedLocales:
        return locale_loc

    for supportedLocale in supportedLocales:
        if supportedLocale.startswith(locale):
            return supportedLocale

    return None
