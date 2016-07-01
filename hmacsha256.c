/*
 * Public domain
 * HMAC-SHA256 implementation
 */

#include "m_pd.h" // INTERFACE: pd interface
#include "hmacsha256.h"

#define MYKEY "best key"

// CLASS: prepare pd class
static t_class *hmacsha256_class; //hmacsha256_class is going to be a pointer to the new class.

// DATA-SPACE: define data-space for class (these are the variables of the pd object)
typedef struct hmacsha256
{
  t_object x_obj; // t_object is used to store internal object-properties like the graphical presentation of the object or data about inlets and outlets
  t_symbol *s_key;
  t_symbol *s_message;
  char *argv;
  int *argc;
} t_hmacsha256; // The structure t_hmacsha256 (of the type _hmacsha256) is the data space of the class

static void hmacsha256_key(t_hmacsha256 *x, int argc, t_atom argv) // int main( int argc, char ** argv )
{
  if( argc != 2 )
  usage( argv[ 0 ] );

  uint8_t key[ BLOCK_LENGTH ];
  normalize_key( key, argv[ 1 ] );

  struct sha256 inner_s;
  sha256_init( &inner_s );

  uint8_t inner_key[ BLOCK_LENGTH ];
  uint8_t outer_key[ BLOCK_LENGTH ];
  for( size_t i = 0; i < BLOCK_LENGTH; i++ ) {
    inner_key[ i ] = key[ i ] ^ INNER_PADDING;
    outer_key[ i ] = key[ i ] ^ OUTER_PADDING;
  }

  sha256_update( &inner_s, inner_key, BLOCK_LENGTH );

  uint8_t buf[ BUFSIZ ];
  size_t n;
  while( ( n = fread( buf, 1, sizeof( buf ), stdin ) ) > 0 )
    sha256_update( &inner_s, buf, n );
  if( ferror( stdin ) )
    err( 1, "error reading stdin" );

  uint8_t inner_hash[ SHA256_DIGEST_LENGTH ];
  sha256_sum( &inner_s, inner_hash );

  struct sha256 outer_s;
  sha256_init( &outer_s );
  sha256_update( &outer_s, outer_key, BLOCK_LENGTH );
  sha256_update( &outer_s, inner_hash, SHA256_DIGEST_LENGTH );

  uint8_t hmac[ SHA256_DIGEST_LENGTH ];
  sha256_sum( &outer_s, hmac );
  for( size_t i = 0; i < SHA256_DIGEST_LENGTH; i++ )
    printf( "%02x", hmac[ i ] );
  putchar( '\n' );

  //return 0;
}

static void hmacsha256_help(t_hmacsha256 *x)
{
  post("A puredata external for computing SHA256 HMACs");
}

static void *hmacsha256_new(t_symbol *s, int argc, t_atom *argv)  
{  
  t_hmacsha256 *x = (t_hmacsha256 *)pd_new(hmacsha256_class);  
 
  outlet_new(&x->x_obj, &s_symbol);  
  return (void *)x;  
}  
 
void hmacsha256_setup(void) {  
  hmacsha256_class = class_new(gensym("hmacsha256"),  
  (t_newmethod)hmacsha256_new,  
  sizeof(t_hmacsha256), 0, A_GIMME, 0);

  class_addanything(hmacsha256_class, (t_method)hmacsha256_key);  
  class_addmethod  (hmacsha256_class, (t_method)hmacsha256_help, gensym("help"), 0); 
}
