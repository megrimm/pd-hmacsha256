/*
 * Public domain
 * HMAC-SHA256 implementation
 */

#include "m_pd.h" // INTERFACE: pd interface
#include "hmacsha256.h"

// CLASS: prepare pd class
static t_class *hmacsha256_class;

// DATA-SPACE: define data-space for class (these are the variables of the pd object)
typedef struct _hmacsha256 {
	t_object x_obj;
	t_symbol *s_key; // store the key
	t_outlet *x_outlet; // data outlet
} t_hmacsha256;

// MEATHOD SPACE???
static void hmacsha256_symbol(t_hmacsha256 *x,t_symbol *s) {
   if(!s->s_name) return;

    outlet_float(x->x_obj.ob_outlet,(t_float)s->s_name[0]);
}

// CONSTRUCTOR
void *hmacsha256_new(t_symbol *s, long argc, long *argv)  
{  
  t_hmacsha256 *x = (t_hmacsha256 *)pd_new(hmacsha256_class); 

  //int main( int argc, char ** argv ) {
	//if( sym != 2 ) // where "sym" is the first inlet? so this is key?
	if( argc != 2 )
		usage( argv[ 0 ] ); //argv would be second inlet (so this is timestamp + etc)

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

	return 0;


  outlet_new(&x->x_obj, &s_symbol);
  return (void *)x;  
}

// SETUP GENERATION
void hmacsha256_setup(void)  
{  
  hmacsha256_class = class_new(gensym("hmacsha256"), (t_newmethod)hmacsha256_new, 0, sizeof(t_hmacsha256), A_DEFSYM, 0);  
 
  class_addsymbol(hmacsha256_class, (t_method)hmacsha256_symbol); // add inlet datatype methods
  //class_addmethod(stat_class,(t_method) stat_set,gensym("key"), A_DEFSYM, 0); // add inlet message methods
}
