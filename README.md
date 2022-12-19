# Introduction

이 README에서는 xrdp-chansrv에서 발견한 취약점 하나 (CVE-2022-23480)와, xrdp에서 발견한 취약점 2개(CVE-2022-23483, CVE-2022-23479)를 소개하고, 이를 이용해 Privilege Escalation까지 도달한 과정을 설명할 것이다.

# What is xrdp?

[xrdp](https://github.com/neutrinolabs/xrdp)는 오픈소스로 운영되는 RDP 서버이다. UNIX-like OS에서 RDP server를 구현하는 것을 목표로 하며 현재 오픈소스 RDP server 중 가장 대중적으로 사용되고 있다.

## The structure of xrdp

xrdp는 여러 개의 바이너리가 상호작용하는 방식으로 RDP server를 구현했다.



![image-20221220082957833](C:\Users\PANDA\AppData\Roaming\Typora\typora-user-images\image-20221220082957833.png)

# The bugs

## Buffer overflow in **devredir_proc_client_devlist_announce_req()**

취약점이 발생하는 `devredir_proc_client_devlist_announce_req` 함수는 rdpdr 채널에서 사용하는 함수로, 클라이언트가 Client Device List Announce 메세지를 보낼 때 이를 파싱하는 역할을 한다.

`devredir_proc_client_devlist_announce_req` 의 전체 코드는 [sesman/chansrv/devredir.c](https://github.com/neutrinolabs/xrdp/blob/v0.9/sesman/chansrv/devredir.c#L787) 에서 찾아볼 수 있다.



이제 어떻게 취약점이 발생하는지 살펴보자. 길이 검증이 없어 BOF가 발생하는 간단한 취약점이다. 앞에서 살펴 봤듯이 **DeviceDataLength** 는 **DeviceData** 의 길이를 결정한다. 그런데 xrdp에서는 **DeviceData**를 저장하는 buffer의 크기가 1024로 만약 **DeviceDataLength** 가 이보다 크다면, BOF가 발생하게 된다.

```c
char g_full_name_for_filesystem[1024];

static void
devredir_proc_client_devlist_announce_req(struct stream *s)
{
    unsigned int i;
    int   j;
    tui32 device_count;
    tui32 device_type;
    tui32 device_data_len;
    char  preferred_dos_name[9];
    enum NTSTATUS response_status;

    /* get number of devices being announced */
    xstream_rd_u32_le(s, device_count);

    LOG_DEVEL(LOG_LEVEL_DEBUG, "num of devices announced: %d", device_count);

    for (i = 0; i < device_count; i++)
    {
        xstream_rd_u32_le(s, device_type);
        xstream_rd_u32_le(s, g_device_id);
        /* get preferred DOS name
         * DOS names that are 8 chars long are not NULL terminated */
        for (j = 0; j < 8; j++)
        {
            preferred_dos_name[j] = *s->p++;
        }
        preferred_dos_name[8] = 0;

        /* Assume this device isn't supported by us */
        response_status = STATUS_NOT_SUPPORTED;

        /* Read the device data length from the stream */
        xstream_rd_u32_le(s, device_data_len);

        switch (device_type)
        {
            case RDPDR_DTYP_FILESYSTEM:
                /* get device data len */
                if (device_data_len)
                {
                    xstream_rd_string(g_full_name_for_filesystem, s,
                                      device_data_len);
                }

                ...
                break;

            case RDPDR_DTYP_SMARTCARD:
                ...
                break;

            default:
            {
                ...
            }
            break;
        }

        ...
    }
}
```

## Out-of-bound read in libxrdp_send_to_channel()

`xrdp_mm_trans_process_channel_data` 는 xrdp-chansrv로 받아온 메세지로부터 `size`, `total_size`를 읽어온다. 그리고 이를 `libxrdp_send_to_channel`의 인자로 넘겨준다.

```c
static int
xrdp_mm_trans_process_channel_data(struct xrdp_mm *self, struct stream *s)
{
    int size;
    int total_size;
    int chan_id;
    int chan_flags;
    int rv;

    in_uint16_le(s, chan_id);
    in_uint16_le(s, chan_flags);
    in_uint16_le(s, size);
    in_uint32_le(s, total_size);
    rv = 0;

    if (rv == 0)
    {
        rv = libxrdp_send_to_channel(self->wm->session, chan_id, s->p, size, total_size,
                                     chan_flags);
    }

    return rv;
}
```

그런데 `libxrdp_send_to_channel` 에서 `data_len (size)`에 대한 검증이 없어 만약 `data`의 길이 보다`data_len` 를 크게 설정한다면 OOB read가 발생하게 된다.

```c
int EXPORT_CC
libxrdp_send_to_channel(struct xrdp_session *session, int channel_id,
                        char *data, int data_len,
                        int total_data_len, int flags)
{
    struct xrdp_rdp *rdp = NULL;
    struct xrdp_sec *sec = NULL;
    struct xrdp_channel *chan = NULL;
    struct stream *s = NULL;

    rdp = (struct xrdp_rdp *)session->rdp;
    sec = rdp->sec_layer;
    chan = sec->chan_layer;
    make_stream(s);
    init_stream(s, data_len + 1024); /* this should be big enough */

    if (xrdp_channel_init(chan, s) != 0)
    {
        LOG(LOG_LEVEL_ERROR, "libxrdp_send_to_channel: xrdp_channel_init failed");
        free_stream(s);
        return 1;
    }

    /* here we make a copy of the data */
    out_uint8a(s, data, data_len);
    s_mark_end(s);
    LOG_DEVEL(LOG_LEVEL_TRACE, "Sending [MS-RDPBCGR] Virtual Channel PDU "
              "data <omitted from log>");

    if (xrdp_channel_send(chan, s, channel_id, total_data_len, flags) != 0)
    {
        LOG(LOG_LEVEL_ERROR, "libxrdp_send_to_channel: xrdp_channel_send failed");
        free_stream(s);
        return 1;
    }

    free_stream(s);
    return 0;
}
```

## Buffer overflow when `header_size` is setted too big in xrdp_mm_chan_data_in()

xrdp-chansrv에서 보낸 메세지를 처리하는 `xrdp_mm_chan_data_in` 에서 `chan_trans->header_size` 를 매우 크게 설정할 수 있다.

```c
static int
xrdp_mm_chan_data_in(struct trans *trans)
{
    struct xrdp_mm *self;
    struct stream *s;
    int size;
    int error;

    ...

    self = (struct xrdp_mm *)(trans->callback_data);
    s = trans_get_in_s(trans);

    ...

    if (trans->extra_flags == 0)
    {
        in_uint8s(s, 4); /* id */
        in_uint32_le(s, size);
        LOG_DEVEL(LOG_LEVEL_DEBUG, "xrdp_mm_chan_data_in: got header, size %d", size);
        if (size > 8)
        {
            self->chan_trans->header_size = size;
            trans->extra_flags = 1;
            return 0;
        }
    }
    /* here, the entire message block is read in, process it */
    error = xrdp_mm_chan_process_msg(self, trans, s);
    self->chan_trans->header_size = 8;
    trans->extra_flags = 0;
    init_stream(s, 0);
    LOG_DEVEL(LOG_LEVEL_DEBUG, "xrdp_mm_chan_data_in: got whole message, reset for "
              "next header");
    return error;
}
```

`header_size` 는 `trans_check_wait_objs` 에서 다음 메세지의 크기를 결정하는데 사용되는데, 이때 만약 `self->in_s` 의 크기보다 `header_size` 가 크다면 BOF가 발생하게 된다.

```c
int
trans_check_wait_objs(struct trans *self)
{
    tbus in_sck = (tbus) 0;
    struct trans *in_trans = (struct trans *) NULL;
    int read_bytes = 0;
    int to_read = 0;
    int read_so_far = 0;
    int rv = 0;
    enum xrdp_source cur_source;

	  ...
		if (self->type1 == TRANS_TYPE_LISTENER) {
				...
		}
    else /* connected server or client (2 or 3) */
    {
        if (self->si != 0 && self->si->source[self->my_source] > MAX_SBYTES)
        {
        }
        else if (self->trans_can_recv(self, self->sck, 0))
        {
            ...
            read_so_far = (int) (self->in_s->end - self->in_s->data);
            to_read = self->header_size - read_so_far;

            if (to_read > 0)
            {
                read_bytes = self->trans_recv(self, self->in_s->end, to_read);

                if (read_bytes == -1)
                {
                    ...
                }
                else if (read_bytes == 0)
                {
                    ...
                }
                else
                {
                    self->in_s->end += read_bytes;
                }
            }

            read_so_far = (int) (self->in_s->end - self->in_s->data);

            if (read_so_far == self->header_size)
            {
                if (self->trans_data_in != 0)
                {
                    rv = self->trans_data_in(self);
                    if (self->no_stream_init_on_data_in == 0)
                    {
                        init_stream(self->in_s, 0);
                    }
                }
            }
            if (self->si != 0)
            {
                self->si->cur_source = cur_source;
            }
        }
        if (trans_send_waiting(self, 0) != 0)
        {
            /* error */
            self->status = TRANS_STATUS_DOWN;
            return 1;
        }
    }

    return rv;
}
```

# Exploitation

일반 사용자 계정 1개를 이용해 xrdp를 exploit하여 root권한의 쉘을 획득할 수 있다.

## How to trigger vuln?

취약점이 발생하는 코드까지 도달하기 위해서는 RDP 에 존재하는 많은 프로토콜들을 이해하고 구현해야 한다. 이는 현실적으로 많은 시간과 노력이 들어가기 때문에 오픈소스 RDP 클라이언트인 FreeRDP를 패치해서 취약점을 트리거 했다.

자세한 패치 내역은 (추후 추가할 github주소)에서 확인할 수 있다.

또한 xrdp에 존재하는 취약점은 xrdp-chansrv와 통신하는 부분에 존재하기 때문에 xrdp-chansrv를 먼저 exploit해서 backdoor를 만들어야 한다.

## Step 1. Exploit the xrdp-chansrv

xrdp-chansrv는 로그인한 유저 권한으로 동작하기 때문에 단순히 쉘을 따는 것은 의미가 없다. backdoor를 만들어 xrdp에 취약한 paylaod를 보내는 것이 해당 단계의 목표이다.

다음 취약점을 이용해 bss영역에 존재하는 다른 전역 변수들을 덮어 쓸 수 있다.

덮어 쓸 수 있는 전역 변수 중 `g_irp_head` 라는 변수가 존재한다.

`devredir_proc_device_iocompletion` 에서 해당 변수를 어떻게 사용하는 지 살펴보자.

`devredir_irp_find` 를 이용해 irp를 찾아오고, `irp->callback`이 NULL이 아니라면 callback을 실행하는 것을 확인할 수 있다.

```c
static void
devredir_proc_device_iocompletion(struct stream *s)
{
    IRP       *irp       = NULL;

    tui32      DeviceId;
    tui32      CompletionId;
    tui32      IoStatus32;
    tui32      Length;
    enum COMPLETION_TYPE comp_type;

    xstream_rd_u32_le(s, DeviceId);
    xstream_rd_u32_le(s, CompletionId);
    xstream_rd_u32_le(s, IoStatus32);
    enum NTSTATUS IoStatus = (enum NTSTATUS) IoStatus32; /* Needed by C++ */

    if ((irp = devredir_irp_find(CompletionId)) == NULL)
    {
        LOG_DEVEL(LOG_LEVEL_ERROR, "IRP with completion ID %d not found", CompletionId);
    }
    else if (irp->callback)
    {
        /* Callback has been set -  call it */
        (*irp->callback)(s, irp, DeviceId, CompletionId, IoStatus);
    }
		else 
		{
				...
		}
		...
}
```

그리고 `devredir_irp_find` 는 `g_irp_head` 부터 `completion_id` 와 `irp->CompletionId` 가 일치하는 irp를 찾아준다.

```c
IRP *devredir_irp_find(tui32 completion_id)
{
    IRP *irp = g_irp_head;

    while (irp)
    {
        if (irp->CompletionId == completion_id)
        {
            LOG_DEVEL(LOG_LEVEL_DEBUG, "returning irp=%p", irp);
            return irp;
        }

        irp = irp->next;
    }

    LOG_DEVEL(LOG_LEVEL_DEBUG, "returning irp=NULL");
    return NULL;
}
```

만약 적절한 fake irp를 구성하고 `g_irp_head`를 fake irp의 주소로 덮는다면 `devredir_proc_device_iocompletion` 을 호출할 때마다 callback으로 실행 흐름을 덮을 수 있다.

이때 callback의 첫 번째 인자로 `s` , 즉 사용자 입력이 들어가는 것을 확인할 수 있다. 따라서 적당한 shellcode를 짜고, 그 주소를 callback에 넣어줘서 사용자 입력을 그대로 xrdp에 보낼 수 있게 된다.

NX로 인해 바로 shellcode를 실행하는 것은 불가능하므로, ROP chain을 잘 구성해서 mmap으로 shellcode를 넣을 메모리를 할당받고, shellcode를 해당 주소에 복사한 뒤 callback을 shellcode의 주소로 덮고, state를 복구 (sp만 복구해줘도 됨) 해주면 성공적으로 backdoor를 만들 수 있다.

이때 필요한 Library, pie, stack leak은 xrdp-chansrv가 로그인한 유저 권한으로 돌아가고 있다는 점을 이용해 `/proc/[pid]/maps` 를 읽어 해결할 수 있다.

## Step 2. Library address & heap address leak

다음 취약점을 이용해 버퍼 밖의 값들을 읽어올 수 있다.

[[cve 보고서 완료\] XRDP 쓸모 있는 OOB Read](https://www.notion.so/cve-XRDP-OOB-Read-0e777ec0a36b4785bcc2189158be92e5)

최대 0x10000 만큼 읽어올 수 있어 libc, heap leak은 항상 성공할 수 있다.

## Step 3. Heap feng shui

굉장히 큰 바이너리이고, alloc과 free가 빈번하게 일어나 heap layout을 예측하기 어려웠다. 취약점을 이용해 버퍼를 굉장히 많이 덮을 수 있었지만, heap layout이 조금이라도 다르면 뭘 해보기도 전에 abort가 발생해 exploit을 더 이상 진행하기 어려웠다.

또한 사용자가 할 수 있는 heap control이 굉장히 제한적이었다. 원하는 크기(0x0 ~ 0xffff) malloc, calloc, calloc 이후 free, free, free가 가장 좋은 heap control이었기 때문에 tcache를 참조하지 않는 calloc 특성 상 tcache chunk의 fd를 overwrite 하는 방식은 사용하기 어려웠다. 그래서 처음엔 fastbin을 이용하려 했지만, 원하는 대로 heap control이 잘 되지 않았다. 차선책으로 다른 곳에서 잘 사용하지 않을만한 크기(smallbin에 들어 갈만한 size)의 chunk를 BOF가 일어나는 chunk의 뒤에 만들고자 했다.

거의 대부분의 상황에서 xrdp의 heap layout은 다음과 같았다.

```c
0x0000 victim (inused, size: 0x2010)
0x2010 chunk 1 (freed / tcache, size: 0x410)
0x2420 chunk 2 (freed / unsorted bin, size: ????)
```

calloc이 chunk를 할당할 때 tcache를 참조하지 않는 것을 이용해 smallbin size중 tcache가 모두 차있는 size의 chunk를 병합되지 않도록 주의하며 할당하고 해제하면, unsorted bin의 크기가 대부분의 경우 해당 size보다 커 victim chunk 조금 뒤에 smallbin에 들어간 chunk를 만들 수 있다.

## Step 4. House of Lore

[how2heap/house_of_lore.c at master · shellphish/how2heap](https://github.com/shellphish/how2heap/blob/master/glibc_2.35/house_of_lore.c)

House of Lore를 이용해 원래 libc나 stack 영역에 chunk를 할당 받을 수 있지만, 선행 조건으로 해당 영역에 fake chunk를 구성해야 하기 때문에 불가능하다. 대신 heap 영역에 fake chunk를 구성하고 fake chunk의 bk->fd에 library 영역의 주소를 쓰는 것은 가능하다.

이를 이용해 사용자 입출력을 관리하는 stream 구조체의 멤버 변수 중 하나인  `end`를 library 영역의 주소로 덮을 수 있었다.

House of Lore를 이용해 `s->end` 를 library 영역의 주소로 덮고, `trans_check_wait_objs` 를 호출하면, `s->end` 뒤에 존재하는 데이터들을 모두 덮을 수 있다.

다만 `to_read` 가 0보다 커야 한다는 조건 때문에 1/2의 확률로 overwrite 할 수 있다.

end는 library 영역의 주소, data는 heap 영역의 주소이므로 aslr이 켜져 있다면 to_read가 0보다 클 확률은 거의 1/2에 가깝다.

```
read_so_far = (int) (self->in_s->end - self->in_s->data);
to_read = self->header_size - read_so_far;
int
trans_check_wait_objs(struct trans *self)
{
    tbus in_sck = (tbus) 0;
    struct trans *in_trans = (struct trans *) NULL;
    int read_bytes = 0;
    int to_read = 0;
    int read_so_far = 0;
    int rv = 0;
    enum xrdp_source cur_source;

    ...

    rv = 0;

    if (self->type1 == TRANS_TYPE_LISTENER) /* listening */
    {
       ...
    }
    else /* connected server or client (2 or 3) */
    {
        if (self->si != 0 && self->si->source[self->my_source] > MAX_SBYTES)
        {
        }
        else if (self->trans_can_recv(self, self->sck, 0))
        {
            cur_source = XRDP_SOURCE_NONE;
            if (self->si != 0)
            {
                cur_source = self->si->cur_source;
                self->si->cur_source = self->my_source;
            }
            read_so_far = (int) (self->in_s->end - self->in_s->data);
            to_read = self->header_size - read_so_far;

            if (to_read > 0)
            {
                read_bytes = self->trans_recv(self, self->in_s->end, to_read);

                ...
            }

            read_so_far = (int) (self->in_s->end - self->in_s->data);

            if (read_so_far == self->header_size)
            {
                if (self->trans_data_in != 0)
                {
                    rv = self->trans_data_in(self);
                    if (self->no_stream_init_on_data_in == 0)
                    {
                        init_stream(self->in_s, 0);
                    }
                }
            }
            if (self->si != 0)
            {
                self->si->cur_source = cur_source;
            }
        }
        if (trans_send_waiting(self, 0) != 0)
        {
            /* error */
            self->status = TRANS_STATUS_DOWN;
            return 1;
        }
    }

    return rv;
}
```

## Step 5. stderr FSOP attack

glibc 2.35에는 hook들이 모두 제거되어 exploit 난이도가 올라갔다. 다행히 main_arena 뒤에 stderr 구조체가 있어 이를 이용해 FSOP를 진행했다.

FSOP도 vtable check가 들어가고 사용할만한 함수들이 패치되긴 했지만, 여전히 유용한 함수들이 몇 가지 존재한다. 이번에는 `_IO_obstack_overflow` 를 이용하여 FSOP를 진행했다.

자세한 방법은 다음 링크에 소개되어 있다.

[[SECCON CTF 2022 Quals\] babyfile](https://nasm.re/posts/babyfile/#obstack-exploitation)

위 링크처럼 stderr 구조체를 적당히 덮어주고 fake obstack 구조체를 만들어 준 뒤, stderr를 사용하는 함수 하나만 호출해주면 된다. 그런데 xrdp 내부 코드에서는 stderr를 사용하는 함수가 없기 때문에 다른 곳에서 쓸만한 함수를 찾아보아야 한다.

`__libc_malloc` 에는 assert 문이 존재하는데 assert 내부의 조건을 만족하면  `__malloc_assert`가 실행되게 된다.

```c
static void
__malloc_assert (const char *assertion, const char *file, unsigned int line,
		 const char *function)
{
  (void) __fxprintf (NULL, "%s%s%s:%u: %s%sAssertion `%s' failed.\\n",
		     __progname, __progname[0] ? ": " : "",
		     file, line,
		     function ? function : "", function ? ": " : "",
		     assertion);
  fflush (stderr);
  abort ();
}
```

실행 흐름을 쭉 따라가 보면

```c
int
__fxprintf (FILE *fp, const char *fmt, ...)
{
  va_list ap;
  va_start (ap, fmt);
  int res = __vfxprintf (fp, fmt, ap, 0);
  va_end (ap);
  return res;
}
```

`fp`에 NULL을 넣어줬기 때문에 `fp` 가 stderr가 된다.

```c
int
__vfxprintf (FILE *fp, const char *fmt, va_list ap,
	     unsigned int mode_flags)
{
  if (fp == NULL)
    fp = stderr;
  _IO_flockfile (fp);
  int res = locked_vfxprintf (fp, fmt, ap, mode_flags);
  _IO_funlockfile (fp);
  return res;
}
```

stderr의 flag를 잘 설정해 주면 다음 함수에 도달하게 된다.

`_IO_sputn`은 vtable를 참조해서 가져오기 때문에 stderr의 vtable을 잘 바꿔주면 FSOP를 성공적으로 할 수 있다.

```c
static int
buffered_vfprintf (FILE *s, const CHAR_T *format, va_list args,
		   unsigned int mode_flags)
{
  CHAR_T buf[BUFSIZ];
  struct helper_file helper;
  FILE *hp = (FILE *) &helper._f;
  int result, to_flush;

  ...

  /* Now flush anything from the helper to the S. */
#ifdef COMPILE_WPRINTF
  if ((to_flush = (hp->_wide_data->_IO_write_ptr
		   - hp->_wide_data->_IO_write_base)) > 0)
    {
      if ((int) _IO_sputn (s, hp->_wide_data->_IO_write_base, to_flush)
	  != to_flush)
	result = -1;
    }
#else
  if ((to_flush = hp->_IO_write_ptr - hp->_IO_write_base) > 0)
    {
      if ((int) _IO_sputn (s, hp->_IO_write_base, to_flush) != to_flush)
	result = -1;
    }
#endif

  /* Unlock the stream.  */
  _IO_funlockfile (s);
  __libc_cleanup_region_end (0);

  return result;
}
```

그럼 `__malloc_assert`를 어떻게 트리거 할 수 있는지 살펴보자. 많은 assert 문들 중 해당 부분을 사용했다.

```c
void *
__libc_malloc (size_t bytes)
{
  mstate ar_ptr;
  void *victim;

  ...
  if (SINGLE_THREAD_P)
    {
      victim = tag_new_usable (_int_malloc (&main_arena, bytes));
      assert (!victim || chunk_is_mmapped (mem2chunk (victim)) ||
	      &main_arena == arena_for_chunk (mem2chunk (victim)));
      return victim;
    }
```

main_arena를 덮을 수 있으므로 `_int_malloc` 이 NON_MAIN_ARENA bit가 set된 fake chunk를 반환하도록 하면, assert문이 실행되어 FSOP를 통해 RCE를 달성할 수 있다.



# Result

![image-20221220083023504](C:\Users\PANDA\AppData\Roaming\Typora\typora-user-images\image-20221220083023504.png)