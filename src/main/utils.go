package main

type Buffer struct {
    data  []byte
    start int
}

func (b *Buffer) PrependBytes(n int) []byte {
    length := cap(b.data) + n
    newData := make([]byte, length)
    copy(newData, b.data)
    b.start = cap(b.data)
    b.data = newData
    return b.data[b.start:]
}

func NewBuffer() *Buffer {
    return &Buffer{
        
    }
}

// 反转字符串
func Reverse(s string) (result string) {
    for _, v := range s {
        result = string(v) + result
    }
    return
}