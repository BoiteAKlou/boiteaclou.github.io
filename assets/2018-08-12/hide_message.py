from PIL import Image
import bitarray
import base64

message = 'YourVerySecretText'
encoded_message = base64.b64encode(message)
#Convert the message into a array of bits
ba = bitarray.bitarray()
ba.frombytes(encoded_message.encode('utf-8'))
bit_array = [int(i) for i in ba]

#Duplicate the original picture
im = Image.open("spongebob.png")
im.save("lsb_spongebob.png")

im = Image.open("lsb_spongebob.png")
width, height = im.size
pixels = im.load()

#Hide message in the first row
i = 0
for x in range(0,width):
    r,g,b = pixels[x,0]
    print("[+] Pixel : [%d,%d]"%(x,0))
    print("[+] \tBefore : (%d,%d,%d)"%(r,g,b))
    #Default values in case no bit has to be modified
    new_bit_red_pixel = 255
    new_bit_green_pixel = 255
    new_bit_blue_pixel = 255

    if i<len(bit_array):
        #Red pixel
        r_bit = bin(r)
        r_last_bit = int(r_bit[-1])
        r_new_last_bit = r_last_bit & bit_array[i]
        new_bit_red_pixel = int(r_bit[:-1]+str(r_new_last_bit),2)
        i += 1

    if i<len(bit_array):
        #Green pixel
        g_bit = bin(g)
        g_last_bit = int(g_bit[-1])
        g_new_last_bit = g_last_bit & bit_array[i]
        new_bit_green_pixel = int(g_bit[:-1]+str(g_new_last_bit),2)
        i += 1

    if i<len(bit_array):
        #Blue pixel
        b_bit = bin(b)
        b_last_bit = int(b_bit[-1])
        b_new_last_bit = b_last_bit & bit_array[i]
        new_bit_blue_pixel = int(b_bit[:-1]+str(b_new_last_bit),2)
        i += 1

    pixels[x,0] = (new_bit_red_pixel,new_bit_green_pixel,new_bit_blue_pixel)
    print("[+] \tAfter: (%d,%d,%d)"%(new_bit_red_pixel,new_bit_green_pixel,new_bit_blue_pixel))

im.save('lsb_spongebob.png')
