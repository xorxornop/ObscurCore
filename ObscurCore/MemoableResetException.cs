using System;

namespace ObscurCore
{
	public class MemoableResetException
		: InvalidCastException
	{
		/*		*
	     * Basic Constructor.
	     *
	     * @param msg message to be associated with this exception.
	     */
		public MemoableResetException(string msg)
			: base(msg)
		{
		}
	}
}

