"""Generic per-profile GitHub message copy recipients; no mailbox inference."""
import re

LOGIN=re.compile(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\Z')
START='<!-- ces-cc:start -->'
END='<!-- ces-cc:end -->'

def unique(users):
    if not isinstance(users,list) or len(users)>100:
        raise RuntimeError('NOTIFICATION_RECIPIENT_LIST_INVALID')
    result={}
    for user in users:
        if not isinstance(user,str) or not LOGIN.fullmatch(user) or '--' in user:
            raise RuntimeError('NOTIFICATION_LOGIN_INVALID')
        result.setdefault(user.casefold(),user)
    return sorted(result.values(),key=str.casefold)

def configured_cc(c):
    return unique(c.get('notifications',{}).get('cc_recipients',[]))

def route(c,primary):
    primary=unique(primary);keys={x.casefold() for x in primary}
    cc=[x for x in configured_cc(c) if x.casefold() not in keys]
    return dict(primary_recipients=primary,cc_recipients=cc,recipients=unique(primary+cc))

def mentions(body):
    return {x.casefold() for x in re.findall(r'(?<![\w@])@([A-Za-z0-9-]+)(?![A-Za-z0-9-])',body)}

def mentions_verified(bodies,users):
    found=set().union(*(mentions(body) for body in bodies))
    return all(user.casefold() in found for user in users)

def message(c,body,primary=None):
    """One managed CC section, without duplicate mentions or changing assignees."""
    cc=configured_cc(c)
    # Empty configuration preserves old byte-level payloads and send ledgers.
    if not cc:return body
    if body.count(START)!=body.count(END) or body.count(START)>1:
        raise RuntimeError('NOTIFICATION_CC_SECTION_INVALID')
    clean=re.sub(re.escape(START)+r'.*?'+re.escape(END),'',body,flags=re.S).rstrip()
    mentioned=mentions(clean)
    mentioned.update(x.casefold() for x in (primary or []))
    copies=[x for x in cc if x.casefold() not in mentioned]
    if not copies:return clean if START in body else body
    return clean+'\n\n'+START+'\n抄送：'+' '.join('@'+x for x in copies)+'\n抄送用于知会，不改变问题负责人或原收件人。\n'+END

def validate_access(c,client):
    cc=configured_cc(c)
    if not cc:return []
    members={x['login'].casefold() for x in client.pages(client.prefix+'/collaborators?affiliation=all')}
    missing=[x for x in cc if x.casefold() not in members]
    if missing:raise RuntimeError('NOTIFICATION_CC_NOT_REPOSITORY_MEMBER:'+','.join(missing))
    return cc
