# -*- coding: utf-8 -*-
"""
Created on Mon Dec 26 17:30:14 2016

Script for studying features for malicious URL

Contextual extraction
@author: Zeyi
"""

import pandas as pd
import numpy as np

import plotly as py
import cufflinks as cf

import tldextract

def read_data():
    """
    Runs through the list of files, and performs csv parsing
    """
    # Malwaredomains list
    df = pd.read_csv("list/domains.txt", header=None, names=['datastr'], comment="#")
    tmp_df = df.datastr.str.split('\t')
    df['domain'] = tmp_df.str[2]
    #df['type'] = tmp_df.str[3]
    df.drop('datastr', axis=1, inplace=True)
    
    # Block.txt
    df2 = pd.read_csv('list/block.txt', header=None, names=['domain'], comment='#')
    
    # Zeustracker - https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist
    df3 = pd.read_csv('list/block.txt', header=None, names=['domain'], comment='#')
    
    #Malwaredomainlist - http://www.malwaredomainlist.com/forums/index.php?topic=3270.0
    df4 = pd.read_csv('list/export.csv', header=None, names=['date','domain','ip','reverse_lookup', 'description','registrant','asn', 'NULL', 'country'], index_col=False)
    blank_indices = df4['domain'] == '-'
    df4.loc[blank_indices, "domain"] = df4.ip[blank_indices]
    df4 = df4['domain']
    
    #Randomware - http://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt
    df5 = pd.read_csv('list/RW_DOMBL.txt', header=None, names=['domain'], comment='#')    
    
    #Suspicious domains (Low sensitivity) - https://isc.sans.edu/feeds/suspiciousdomains_Low.txt
    df6 = pd.read_csv('list/suspiciousdomains_Low.txt', header=None, names=['domain'], comment='#') 
    
    df_all = pd.concat([df, df2, df3, df4, df5, df6], ignore_index=True)
    
    print "Total entries: %d" % (len(df_all))
    df_all = pd.DataFrame(df_all.domain.unique(), columns=['domain'])
    df_all.dropna(inplace=True)
    print "Unique entries: %d" % (len(df_all))
    return df_all
    
def extract_tld(url, tldobj=None, dom_lvl='tld'):
    """
    Performs a map to extract information from domain. 
    Inputs:
        url: [str] str of url. This DOES NOT validate the URL
        tldobj: Defined tldextract object to use
        type: {'tld', 'sld', 'domain'}. Default='tld'. Defines type of information to extract. domain is for tld+sld
    """
    if tldobj is None:
        tldobj = tldextract.TLDExtract()
    ext = tldobj(url)
    
    if dom_lvl == 'sld':
        return ext[1]
    elif dom_lvl == 'tld':
        if ext[2] is None: #No valid tld found. Return final tld. 
        #TODO: Does not work for IP. Need a separate check
            return url.split('.')[-1]
        else:
            return ext[2]
    elif dom_lvl == 'domain':
        if ext[2] is None: #No valid tld found. Return entire url
            return url
        else:
            return '.'.join(part for part in ext[1:] if part)
    elif dom_lvl == 'subdomain':
        return ext[0]
    elif dom_lvl == 'all':
        return [ext[0], ext[1], ext[2]]
    else: #Invalid type
        raise('InvalidTypeError')

def strip_www(series):
    """
    Strip urls starting with www. (And remove from string)
    """
    starts_with_www = series.str.startswith('www.')
    series.loc[starts_with_www] = series[starts_with_www].str.replace('www.', '', 1)
    return series
#    
#def extract_tld(url, tldobj=None):
#    """
#    Performs a map to extract TLD
#    """
#    if tldobj is None:
#        tldobj = tldextract.TLDExtract()
#    ext = tldobj(url)
#    
#
#
#def extract_sld(url, tldobj=None):
#    """
#    Performs extraction of SLD
#    """
#    if tldobj is None:
#        tldobj = tldextract.TLDExtract()
#    ext = tldobj(url)
#    
#    return ext[1]       
    
def initialise_tldextract():
    """
    Returns two tldextract objects. One referring to the private list, one with the public list config
    E.G. private('www.xiaxue.blogspot.sg') -> www xiaxue blogspot.com.sg
    public('www.xiaxue.blogspot.sg') -> www.xiaxue blogspot com.sg
    ASSUMES THAT APPROPRIATE CACHE FILES HAVE BEEN CREATED! (Requires internet connection)
    This fix is required due to a bug in tldextract (See #66: https://github.com/john-kurkowski/tldextract/issues/66)
    """
    #Extract path name from module file
    init_path = tldextract.__file__
    index = init_path.rfind('\\') #Find the ending slash position
    base_path = init_path[:index]
    
    pub_ext = tldextract.TLDExtract(include_psl_private_domains=False,
                                    suffix_list_urls=None,
                                    cache_file=base_path+'\\Normal.tld_set')
    priv_ext = tldextract.TLDExtract(include_psl_private_domains=True,
                                    suffix_list_urls=None,
                                    cache_file=base_path+'\\Private.tld_set')                
    return pub_ext, priv_ext

def split_url(s, tgt_col, tldobj=None):
    """
    Performs url structure splitting on tgt_col. s is a pandas series (can get from apply function with axis=1)
    Will extract 
    sld 
    tld 
    subdomain
    """
    if tldobj is None:
        tldobj = tldextract.TLDExtract()
    ext = tldobj(s[tgt_col])
    s['tld'] = ext[2]
    s['sld'] = ext[1]
    s['subdomain'] = ext[0]
    return s
    
def augment_lexical(df, tgt_col='domain'):
    """
    Inserts columns 
    'sld':(Second level domain)
    'tld': (Top level domain)
    'dom_depth': Subdomain depth. 0 for no subdomain.
    'dom_alpha': Proportion of alphabetical domain characters in SLD
    'sld_len': SLD length
    TLD uses the normal public suffix list. SLD extraction looks at public domain extension.
    N.B. Please strip domains of www before using this function
    """
    pub_ext, priv_ext = initialise_tldextract()
    
    df[tgt_col] = strip_www(df[tgt_col])
    #Extract a copy of the target column, then perform unique
    #This is to reduce workload on tldextract
    tmp_df = df[[tgt_col]].drop_duplicates()
    
    #Extract TLD
    #tmp_df = tmp_df.apply(split_url, axis=1, tgt_col=tgt_col, tldobj=pub_ext)
    tmp_df['dom_split'] = tmp_df[tgt_col].apply(extract_tld, tldobj=pub_ext, dom_lvl='all')
    tmp_df['tld'] = tmp_df['dom_split'].str[2] #Trick from Wes
    tmp_df['sld'] = tmp_df['dom_split'].str[1]
    tmp_df['subdomain'] = tmp_df['dom_split'].str[0]
    #tmp_df['tld'] = tmp_df[tgt_col].apply(extract_tld, tldobj=pub_ext, type='tld')
    
    #Extract SLD 
    #tmp_df['sld'] = tmp_df[tgt_col].apply(extract_tld, tldobj=pub_ext, type='sld')
    
    #Extract SLD+TLD [optional]
    #tmp_df['host'] = tmp_df[tgt_col].apply(extract_tld, tldobj=priv_ext, type='domain')
    
    #Extract sld length
    tmp_df['sld_len'] = tmp_df['sld'].str.len()
    
    #Count alphanumeric ratio
    tmp_df['dom_alpha'] = (1.0 * tmp_df['sld'].str.count(r'[0-9]')) / tmp_df['sld_len']
    
    #Count number of subdomain levels
    tmp_df['dom_depth'] = tmp_df['subdomain'].str.count(r'\.') + 1
    tmp_df.loc[tmp_df['subdomain'] == "", 'dom_depth'] = 0
    
    #House-keeping
    tmp_df.drop('dom_split', axis=1, inplace=True)
    
    #Join back
    df = df.merge(tmp_df, on='domain')
    return df
    
    
if __name__ == "__main__":
    
    #Read data
    bad_dom_df = read_data()
    alexa_df = pd.read_csv('top-1m.csv',header=None, names=['rank','domain'])
    alexa_df.drop('rank', axis=1, inplace=True)
    
    pub_ext, priv_ext = initialise_tldextract()
    
    #Perform some basic feature extraction
    bad_dom_df = augment_lexical(bad_dom_df)
#    bad_dom_df['tld'] = bad_dom_df['domain'].apply(extract_tld, tldobj=pub_ext)
    #alexa_df['tld'] = alexa_df['domain'].apply(extract_tld, tldobj=tldextract.TLDExtract())
    
    #Extract SLDs and count
    sld_count = bad_dom_df.groupby('sld').agg({'domain':['count','unique'], 'tld':['unique', 'nunique']})
    #Count the tlds and visualize
#    tld_count = bad_dom_df.groupby('tld')['domain'].count()
#    tld_count.sort_values(inplace=True, ascending=False)
#    cf.set_config_file(offline=True, world_readable=True, theme='ggplot')
#    cf_test = tld_count.iplot(kind='bar',
#                        title='TLD distribution',yTitle='Visits',xTitle='Sites',
#                        online=False,asFigure=True)
#    py.offline.plot(cf_test, filename='tld_distribution.html')
    
    #pub_ext, priv_ext = initialise_tldextract()
    