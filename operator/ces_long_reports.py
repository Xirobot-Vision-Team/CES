"""Lossless UTF-8 report sections for one GitHub report thread."""
import ces_workflow as w

PART_BYTES=40000
MAX_REPORT_BYTES=1024*1024 # Match the repository document publisher's per-file ceiling.
MAX_PARTS=128
END='<!-- ces-report-part-end -->'

def split_body(body,limit=PART_BYTES):
    w.need(isinstance(body,str) and 1024<=limit<=PART_BYTES,'LONG_REPORT_INPUT_INVALID')
    w.need(len(body.encode('utf-8'))<=MAX_REPORT_BYTES,'LONG_REPORT_TOTAL_LIMIT')
    chunks=[];remaining=body
    while len(remaining.encode('utf-8'))>limit:
        prefix=remaining.encode('utf-8')[:limit].decode('utf-8',errors='ignore')
        # Prefer paragraph/line boundaries, never discard whitespace or bytes.
        end=prefix.rfind('\n\n')
        if end>=len(prefix)//2:end+=2
        else:
            end=prefix.rfind('\n')
            end=end+1 if end>=len(prefix)//2 else len(prefix)
        chunks.append(remaining[:end]);remaining=remaining[end:]
    chunks.append(remaining)
    w.need(len(chunks)<=MAX_PARTS and ''.join(chunks)==body,'LONG_REPORT_SPLIT_INVALID')
    return chunks

def publish(client,topic,snapshot,title,body,recipients):
    chunks=split_body(body);count=len(chunks)
    identity=w.sha(body);parts=[];number=None
    # Prepare every message before the first external write, including CC overhead.
    from ces_notifications import message
    payloads=[]
    for index,chunk in enumerate(chunks,1):
        content=(f'本报告共 {count} 篇，均位于同一报告线程；仅在末篇到齐后才是完整报告。\n\n'
                 f'## 报告正文 {index}/{count}\n\n'+chunk+'\n'+END)
        if index==count:content+='\n\n报告末篇；完整正文 SHA-256：'+identity
        w.need(len(message(client.c,content,recipients).encode('utf-8'))<50000,'LONG_REPORT_PART_LIMIT')
        payloads.append(content)
    for index,content in enumerate(payloads,1):
        part_snapshot=w.sha(str(snapshot)+'\0'+identity+'\0v1\0'+str(index)+'/'+str(count))
        result=client._publish_one(topic,part_snapshot,title,content,recipients,thread_number=number)
        if number is None:number=result['number']
        parts.append(result)
    first=parts[0]
    return {**first,'status':'duplicate_skipped' if all(x['status']=='duplicate_skipped' for x in parts) else 'published_multipart_readback_verified',
            'multipart':True,'part_count':count,'body_sha256':identity,'parts':parts,
            'content_snapshot':snapshot,'all_parts_readback_verified':True}
